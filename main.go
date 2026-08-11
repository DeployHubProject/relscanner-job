// Ortelius v11 Vulnerability Microservice that handles creating Vulnerability from OSV.dev
// Runs as a cronjob
//
// CRITICAL FIXES APPLIED:
// 1. Restored Robust Materialized Edge logic (release2cve) from working snippet
// 2. Fixed cve2purl Hub population to prevent empty collections
// 3. Permanent Fix for Bad Dates using DATE_ISO8601 and DATE_TIMESTAMP
// 4. Maintained Go-side and AQL version validation
// 5. Normalized all outgoing timestamps to RFC3339 strings for AQL compatibility
// 6. BACKEND CONSISTENCY: Matching validation logic with restapi/modules/releases/handlers.go
// 7. IMPROVED FORMATTING: All AQL queries formatted for maximum readability
// 8. OPTIMIZATION: Uses If-Modified-Since headers to skip unchanged zip downloads from GCS
package main

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/ortelius/v12/database"
	"github.com/ortelius/ortelius/v12/restapi/modules/lifecycle"
	"github.com/ortelius/ortelius/v12/util"
)

var logger = database.InitLogger()
var dbconn = database.InitializeDatabase()

// ============================================================================
// HTTP tunables
//
// All overridable by env var so the CronJob can be retuned without a rebuild.
// Defaults are chosen so a worst-case run stays under activeDeadlineSeconds
// (780s) in the Helm chart:
//   perRequestTimeout (240s) x maxAttempts is bounded per ecosystem, and a
//   failed ecosystem is skipped rather than aborting the whole run.
// ============================================================================

var (
	dialTimeout           = envDuration("OSV_DIAL_TIMEOUT", 10*time.Second)
	tlsHandshakeTimeout   = envDuration("OSV_TLS_TIMEOUT", 10*time.Second)
	responseHeaderTimeout = envDuration("OSV_RESPONSE_HEADER_TIMEOUT", 60*time.Second)
	perRequestTimeout     = envDuration("OSV_REQUEST_TIMEOUT", 240*time.Second)
	maxAttempts           = envInt("OSV_MAX_ATTEMPTS", 3)
	maxBodyBytes          = int64(envInt("OSV_MAX_BODY_MB", 2048)) << 20
)

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// httpGetWithRetry fetches url with a per-attempt context deadline, so a
// stalled read is cancelled rather than hanging indefinitely. Retries on
// timeout and on 5xx; 4xx is returned immediately since retrying will not
// help. The body is capped at maxBodyBytes to bound memory.
func httpGetWithRetry(client *http.Client, urlStr, label string) ([]byte, error) {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		start := time.Now()

		ctx, cancel := context.WithTimeout(context.Background(), perRequestTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("%s: build request: %w", label, err)
		}

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if errors.Is(err, context.DeadlineExceeded) {
				logger.Sugar().Warnf("%s: attempt %d/%d timed out after %s", label, attempt, maxAttempts, time.Since(start).Round(time.Millisecond))
			} else {
				logger.Sugar().Warnf("%s: attempt %d/%d failed after %s: %v", label, attempt, maxAttempts, time.Since(start).Round(time.Millisecond), err)
			}
			backoff(attempt)
			continue
		}

		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			resp.Body.Close()
			cancel()
			return nil, fmt.Errorf("%s: HTTP %d", label, resp.StatusCode)
		}
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("%s: HTTP %d", label, resp.StatusCode)
			logger.Sugar().Warnf("%s: attempt %d/%d got HTTP %d", label, attempt, maxAttempts, resp.StatusCode)
			backoff(attempt)
			continue
		}

		// Read one byte past the cap so truncation is detected instead of
		// silently returning a partial body.
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		resp.Body.Close()
		cancel()
		if err != nil {
			lastErr = err
			logger.Sugar().Warnf("%s: attempt %d/%d body read failed after %s: %v", label, attempt, maxAttempts, time.Since(start).Round(time.Millisecond), err)
			backoff(attempt)
			continue
		}
		if int64(len(body)) > maxBodyBytes {
			return nil, fmt.Errorf("%s: response exceeds OSV_MAX_BODY_MB limit (%d MB)", label, maxBodyBytes>>20)
		}

		logger.Sugar().Debugf("%s: fetched %d bytes in %s (attempt %d)", label, len(body), time.Since(start).Round(time.Millisecond), attempt)
		return body, nil
	}

	return nil, fmt.Errorf("%s: all %d attempts failed: %w", label, maxAttempts, lastErr)
}

// downloadZipWithRetry streams url to a temp file and opens it as a zip.
//
// Streaming to disk (rather than io.ReadAll into memory) keeps large
// ecosystems such as Ubuntu from blowing the pod memory limit, and lets us
// validate the archive before use. A truncated body (size cap hit, short
// read vs Content-Length, or an unreadable zip central directory) is treated
// as a retryable failure instead of surfacing later as
// "zip: not a valid zip file". The caller must call cleanup() when done.
func downloadZipWithRetry(client *http.Client, urlStr, label string, lastRun time.Time) (*zip.ReadCloser, func(), bool, error) {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		start := time.Now()

		zr, cleanup, isNotModified, retry, err := downloadZipOnce(client, urlStr, label, lastRun)
		if err == nil {
			if !isNotModified {
				logger.Sugar().Debugf("%s: fetched zip in %s (attempt %d)", label, time.Since(start).Round(time.Millisecond), attempt)
			}
			return zr, cleanup, isNotModified, nil
		}
		if !retry {
			return nil, nil, false, err
		}

		lastErr = err
		logger.Sugar().Warnf("%s: attempt %d/%d failed after %s: %v", label, attempt, maxAttempts, time.Since(start).Round(time.Millisecond), err)
		if attempt < maxAttempts {
			backoff(attempt)
		}
	}

	return nil, nil, false, fmt.Errorf("%s: all %d attempts failed: %w", label, maxAttempts, lastErr)
}

// downloadZipOnce performs a single attempt. The bool result reports whether
// a failure is worth retrying. The first bool indicates if the file is unmodified (HTTP 304).
func downloadZipOnce(client *http.Client, urlStr, label string, lastRun time.Time) (*zip.ReadCloser, func(), bool, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), perRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, nil, false, false, fmt.Errorf("%s: build request: %w", label, err)
	}

	// Add dynamic caching validation headers using standard RFC7231 time format
	if !lastRun.IsZero() {
		req.Header.Set("If-Modified-Since", lastRun.UTC().Format(http.TimeFormat))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, false, true, err
	}
	defer resp.Body.Close()

	// Handle GCS HTTP 304 Not Modified optimization early (no transmission body payload)
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil, true, false, nil
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, nil, false, false, fmt.Errorf("%s: HTTP %d", label, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, false, true, fmt.Errorf("%s: HTTP %d", label, resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "osv-*.zip")
	if err != nil {
		return nil, nil, false, false, fmt.Errorf("%s: create temp file: %w", label, err)
	}
	cleanup := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}

	// One byte past the cap so oversize is detected rather than truncated.
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		cleanup()
		return nil, nil, false, true, fmt.Errorf("body read failed after %d bytes: %w", n, err)
	}
	if n > maxBodyBytes {
		cleanup()
		return nil, nil, false, false, fmt.Errorf("%s: archive exceeds OSV_MAX_BODY_MB limit (%d MB)", label, maxBodyBytes>>20)
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		cleanup()
		return nil, nil, false, true, fmt.Errorf("short read: got %d of %d bytes", n, resp.ContentLength)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, nil, false, true, err
	}

	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		os.Remove(tmp.Name())
		return nil, nil, false, true, fmt.Errorf("invalid zip (%d bytes received): %w", n, err)
	}

	return zr, func() {
		zr.Close()
		os.Remove(tmp.Name())
	}, false, false, nil
}

func backoff(attempt int) {
	time.Sleep(time.Duration(attempt) * 2 * time.Second)
}

// ============================================================================
// Main Import Logic
// ============================================================================

func LoadFromOSVDev() {
	baseURL := "https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/ecosystems.txt?alt=media"

	// Bounded transport. Without these, a stalled TCP read blocks forever:
	// a single slow ecosystem fetch pushed a run past its 15 minute schedule,
	// and concurrencyPolicy: Forbid then skipped every subsequent tick.
	//
	// ResponseHeaderTimeout bounds the wait for the first byte. The body read
	// itself is bounded per-request by the context in httpGetWithRetry, since
	// a flat Client.Timeout would also cap large legitimate downloads.
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12},
		MaxIdleConns:          100,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}
	client := &http.Client{Transport: tr}

	body, err := httpGetWithRetry(client, baseURL, "ecosystems.txt")
	if err != nil {
		logger.Sugar().Fatal(err)
	}

	lines := strings.Split(string(body), "\n")
	totalCVEsUpdated := 0

	for _, line := range lines {
		platform := strings.TrimSpace(line)
		if len(platform) == 0 {
			continue
		}

		cveCount := processEcosystem(client, platform)
		totalCVEsUpdated += cveCount
	}

	if totalCVEsUpdated > 0 {
		logger.Sugar().Infof("All ecosystems processed. Total CVEs updated: %d. Running lifecycle tracking...", totalCVEsUpdated)
		if err := updateLifecycleForNewCVEs(totalCVEsUpdated); err != nil {
			logger.Sugar().Warnf("Failed to update lifecycle tracking after CVE updates: %v", err)
		} else {
			logger.Sugar().Infof("Lifecycle tracking update complete")
		}
	} else {
		logger.Sugar().Infof("No CVE updates. Skipping lifecycle tracking.")
	}
}

// ============================================================================
// Ecosystem Processing
// ============================================================================

func processEcosystem(client *http.Client, platform string) int {
	// Stay under the Job's activeDeadlineSeconds so the run exits cleanly
	// (and lifecycle tracking still runs) instead of being killed.
	if runBudgetExceeded() {
		logger.Sugar().Infof("Ecosystem: %s | run budget exhausted, deferring to next run", platform)
		return 0
	}

	lastRunTime, _ := util.GetLastRun(dbconn, platform)

	// Incremental path: read <eco>/modified_id.csv and fetch only changed records.
	// Falls back to all.zip on first load, CSV failure, or very large backlog.
	if !lastRunTime.IsZero() {
		if n, handled := processIncremental(client, platform, lastRunTime); handled {
			return n
		}
	}

	urlStr := fmt.Sprintf("https://www.googleapis.com/download/storage/v1/b/osv-vulnerabilities/o/%s%%2Fall.zip?alt=media", url.PathEscape(platform))

	start := time.Now()

	zipReader, cleanup, isNotModified, err := downloadZipWithRetry(client, urlStr, platform, lastRunTime)
	if err != nil {
		// A single bad ecosystem must not abort the run. Skipping it means
		// the next scheduled tick retries it; hanging here means every
		// subsequent tick is skipped by concurrencyPolicy: Forbid.
		logger.Sugar().Errorf("Ecosystem: %s | SKIPPED after %s: %v", platform, time.Since(start).Round(time.Millisecond), err)
		return 0
	}

	// Exit early if GCS verified the file has not been modified since our last check
	if isNotModified {
		logger.Sugar().Infof("Ecosystem: %s | Unchanged since last run (%s). Skipping download & processing.", platform, lastRunTime.Format(time.RFC3339))
		return 0
	}
	defer cleanup()

	downloadDur := time.Since(start)

	var maxSeenTime = lastRunTime
	var cveCount int

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() || strings.Contains(f.Name, "/") {
			continue
		}

		func() {
			rc, err := f.Open()
			if err != nil {
				return
			}
			defer rc.Close()

			var content map[string]interface{}
			if err := json.NewDecoder(rc).Decode(&content); err != nil {
				return
			}

			modStr, _ := content["modified"].(string)
			if modStr != "" {
				modTime, err := time.Parse(time.RFC3339, modStr)
				if err == nil {
					if modTime.After(maxSeenTime) {
						maxSeenTime = modTime
					}
					if !modTime.After(lastRunTime) {
						return
					}
				}
			}

			if ingestRecord(content) {
				cveCount++
			}
		}()
	}

	if cveCount > 0 {
		if maxSeenTime.IsZero() {
			maxSeenTime = time.Now().UTC()
		}
		logger.Sugar().Infof("Ecosystem: %s | New CVEs: %d | download=%s total=%s | Updating high water mark to %s",
			platform, cveCount, downloadDur.Round(time.Millisecond), time.Since(start).Round(time.Millisecond), maxSeenTime.Format(time.RFC3339))
		util.SaveLastRun(dbconn, platform, maxSeenTime)
	} else {
		logger.Sugar().Infof("Ecosystem: %s | No new CVEs found | download=%s total=%s",
			platform, downloadDur.Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
	}

	return cveCount
}

// ============================================================================
// CVE Document Processing
// ============================================================================

func newVuln(content map[string]interface{}) (bool, error) {
	var ctx = context.Background()
	id, ok := content["id"].(string)
	if !ok || id == "" {
		return false, nil
	}

	cveKey := util.SanitizeKey(id)
	content["_key"] = cveKey
	content["objtype"] = "CVE"

	// Check if already processed with same modification date
	modDate, _ := content["modified"].(string)
	parameters := map[string]interface{}{"key": cveKey}

	checkModQuery := `
		FOR vuln IN cve 
			FILTER vuln._key == @key 
			RETURN vuln.modified
	`

	cursor, err := dbconn.Database.Query(ctx, checkModQuery, &arangodb.QueryOptions{
		BindVars: parameters,
	})
	if err == nil {
		defer cursor.Close()
		if cursor.HasMore() {
			var existingMod string
			if _, err := cursor.ReadDocument(ctx, &existingMod); err == nil {
				if existingMod == modDate {
					return false, nil // No update needed
				}
			}
		}
	}

	// Skip CVEs without affected packages
	if _, exists := content["affected"]; !exists {
		return false, nil
	}

	// Record the normalized base purl of every affected entry on the document.
	// The backend finds a package's CVEs through an index on it when it builds
	// edges lazily (LAZY_CVE_EDGES), so it must be stored with the CVE.
	annotateBasePurls(content)

	// Upsert CVE document
	upsertQuery := `
		UPSERT { _key: @key } 
		INSERT @doc 
		UPDATE @doc 
		IN cve
	`
	bindVars := map[string]interface{}{
		"key": cveKey,
		"doc": content,
	}

	if _, err := dbconn.Database.Query(ctx, upsertQuery, &arangodb.QueryOptions{
		BindVars: bindVars,
	}); err != nil {
		return false, err
	}

	// Populate cve2purl Hub edges. The CVE document is written above, before any
	// edge: in lazy mode the backend does the opposite for a newly referenced
	// package (package and sbom2purl edge first, then the CVE lookup), so
	// whichever side goes second sees the other's write and one of them creates
	// the edge.
	if err := processEdges(ctx, content); err != nil {
		logger.Sugar().Errorf("cve2purl edges for %s were not written: %v", id, err)
	}

	return true, nil
}

// githubRepoToPURL converts a GitHub repository URL to a pkg:github PURL.
// "https://github.com/curl/curl.git" → "pkg:github/curl/curl"
func githubRepoToPURL(repoURL string) string {
	repoURL = strings.TrimSuffix(strings.TrimSuffix(repoURL, "/"), ".git")

	const githubPrefix = "https://github.com/"
	if !strings.HasPrefix(repoURL, githubPrefix) {
		return ""
	}

	parts := strings.Split(strings.TrimPrefix(repoURL, githubPrefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}

	// Reuse the shared, centrally-normalized purl builder instead of
	// hand-rolling the string, so github owner/repo casing matches every
	// other consumer (e.g. SBOM component purls built the same way).
	return util.GetBasePURLFromComponents("Github", parts[0], parts[1])
}

// resolvePURL attempts to determine a base PURL for an affected entry using
// a four-tier fallback strategy:
//
//  1. affected.package.purl         — explicit PURL (most ecosystems)
//  2. affected.package.ecosystem    — synthesise from ecosystem + name
//  3. affected.ranges[GIT].repo     — synthesise pkg:github from repo URL (C/C++)
//  4. database_specific.package     — last resort pkg:generic
func resolvePURL(affMap map[string]interface{}, content map[string]interface{}) string {
	// Tier 1 & 2 — package block present
	if pkgMap, ok := affMap["package"].(map[string]interface{}); ok {
		if purl, ok := pkgMap["purl"].(string); ok && purl != "" {
			cleaned, err := util.CleanPURL(purl)
			if err != nil {
				return ""
			}
			basePurl, err := util.GetStandardBasePURL(cleaned)
			if err != nil {
				return ""
			}
			return basePurl
		}

		ecosystem, _ := pkgMap["ecosystem"].(string)
		namespace, _ := pkgMap["namespace"].(string)
		name, _ := pkgMap["name"].(string)
		if ecosystem != "" && name != "" {
			// Julia is a registered purl type (added to the purl-spec Oct 2025):
			// pkg:julia/<Name> — no namespace, case preserved (Julia package
			// names are case-sensitive, e.g. HTTP != http). This must match
			// what real Julia SBOM tools (Trivy, PkgToSoftwareBOM.jl) emit,
			// so the JLL suffix (e.g. rsync_jll) is kept as-is rather than
			// resolved to the wrapped upstream library name.
			if strings.EqualFold(ecosystem, "Julia") {
				return "pkg:julia/" + name
			}
			return util.GetBasePURLFromComponents(ecosystem, namespace, name)
		}
	}

	// Tier 3 — find the first GIT range and extract repo URL
	if ranges, ok := affMap["ranges"].([]interface{}); ok {
		for _, rangeItem := range ranges {
			rangeMap, ok := rangeItem.(map[string]interface{})
			if !ok || rangeMap["type"] != "GIT" {
				continue
			}
			if repo, ok := rangeMap["repo"].(string); ok {
				if purl := githubRepoToPURL(repo); purl != "" {
					return purl
				}
			}
			break // only need the first GIT range
		}
	}

	// Tier 4 — database_specific.package as pkg:generic last resort
	if dbSpecific, ok := content["database_specific"].(map[string]interface{}); ok {
		if pkgName, ok := dbSpecific["package"].(string); ok && pkgName != "" {
			logger.Sugar().Warnf("Using pkg:generic fallback for package %q — consider improving OSV record", pkgName)
			return "pkg:generic/" + strings.ToLower(pkgName)
		}
	}

	return ""
}

// lazyEdgesEnabled reports whether edges are written lazily (LAZY_CVE_EDGES=true):
// only for packages an SBOM already references, instead of for every package of
// every advisory.
func lazyEdgesEnabled() bool {
	return strings.EqualFold(os.Getenv("LAZY_CVE_EDGES"), "true")
}

// entryBasePurl returns the base purl of an affected entry: the value stored on
// it by annotateBasePurls, or resolved from the entry.
func entryBasePurl(affMap map[string]interface{}, content map[string]interface{}) string {
	if p, ok := affMap["base_purl"].(string); ok && p != "" {
		return p
	}
	return resolvePURL(affMap, content)
}

// annotateBasePurls stores the resolved base purl on each affected entry as
// base_purl, so it is written with the CVE document.
func annotateBasePurls(content map[string]interface{}) {
	affected, _ := content["affected"].([]interface{})
	for _, item := range affected {
		aff, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if p := resolvePURL(aff, content); p != "" {
			aff["base_purl"] = p
		}
	}
}

// findActiveHubs returns, for the base purls of a CVE's affected entries, the
// package nodes (purl -> "purl/<key>") that an SBOM references, i.e. that have
// an sbom2purl edge pointing at them.
func findActiveHubs(ctx context.Context, affected []interface{}, content map[string]interface{}) (map[string]string, error) {
	seen := make(map[string]bool)
	var purls []string
	for _, item := range affected {
		aff, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if p := entryBasePurl(aff, content); p != "" && !seen[p] {
			seen[p] = true
			purls = append(purls, p)
		}
	}

	active := make(map[string]string)
	if len(purls) == 0 {
		return active, nil
	}

	// purl has a unique index on its purl attribute, and sbom2purl an edge
	// index on _to, so this is a handful of index lookups per CVE.
	const query = `
		FOR p IN @purls
			FOR h IN purl
				FILTER h.purl == p
				FILTER LENGTH(FOR s IN sbom2purl FILTER s._to == h._id LIMIT 1 RETURN 1) > 0
				RETURN { purl: p, id: h._id }
	`
	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{"purls": purls},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	for cursor.HasMore() {
		var row struct {
			Purl string `json:"purl"`
			ID   string `json:"id"`
		}
		if _, err := cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		active[row.Purl] = row.ID
	}
	return active, nil
}

// edgeVersionKeys are the numeric version parts a cve2purl edge may carry.
var edgeVersionKeys = []string{
	"introduced_major", "introduced_minor", "introduced_patch",
	"fixed_major", "fixed_minor", "fixed_patch",
	"last_affected_major", "last_affected_minor", "last_affected_patch",
}

// processEdges populates purl hub nodes and cve2purl edges.
// SEMVER and ECOSYSTEM ranges are stored; GIT ranges are skipped as commit SHAs
// cannot be used for version range matching.
//
// ECOSYSTEM ranges (PyPI, Maven, NuGet, RubyGems, Debian, ...) use the
// ecosystem's own version ordering, which is not semver (PEP 440 pre/post
// releases and epochs, Maven qualifiers, ...). Their edge therefore carries no
// numeric version parts, which makes the matching queries hand every candidate
// to util.IsVersionAffected -- the ecosystem-aware check that also honours the
// advisory's explicit versions list -- instead of comparing major/minor/patch
// in AQL. Skipping these ranges (as this used to) left no cve2purl edge at all,
// so no release was ever linked to the CVE.
func processEdges(ctx context.Context, content map[string]interface{}) error {
	cveID, _ := content["id"].(string)
	cveKey := util.SanitizeKey(cveID)
	cveDocID := "cve/" + cveKey

	affected, ok := content["affected"].([]interface{})
	if !ok || len(affected) == 0 {
		return nil
	}

	// Lazy mode: only packages some SBOM already references get edges, so the
	// loader never creates package nodes or edges for packages no release
	// contains. A package that is first referenced later gets its edges from
	// the backend (sbom.EnsureCVEEdgesForPurls), found through base_purl.
	lazy := lazyEdgesEnabled()
	var activeHubs map[string]string
	if lazy {
		var err error
		activeHubs, err = findActiveHubs(ctx, affected, content)
		if err != nil {
			return fmt.Errorf("looking up referenced packages: %w", err)
		}
		if len(activeHubs) == 0 {
			return nil
		}
	}

	for _, affItem := range affected {
		affMap, ok := affItem.(map[string]interface{})
		if !ok {
			continue
		}

		basePurl := entryBasePurl(affMap, content)
		if basePurl == "" {
			logger.Sugar().Warnf("Could not resolve PURL for CVE %s, skipping affected entry", cveID)
			continue
		}

		purlKey := util.SanitizeKey(basePurl)
		purlDocID := "purl/" + purlKey

		if lazy {
			// Use the package node the SBOM side created (found by its unique
			// purl), not one keyed by us: a node the backend created first has
			// an auto-generated key, and inserting a second one with the same
			// purl is rejected by the unique index on purl.
			hubID, active := activeHubs[basePurl]
			if !active {
				continue
			}
			purlDocID = hubID
		} else {
			purlNode := map[string]interface{}{
				"_key":    purlKey,
				"purl":    basePurl,
				"objtype": "PURL",
			}

			purlUpsertQuery := `
				UPSERT { _key: @key }
				INSERT @doc
				UPDATE {}
				IN purl
			`
			if _, err := dbconn.Database.Query(ctx, purlUpsertQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"key": purlKey,
					"doc": purlNode,
				},
			}); err != nil {
				// Don't create a cve2purl edge pointing at a purl document
				// that was never actually written -- that produces a
				// permanently-dangling edge (ArangoDB doesn't enforce
				// referential integrity on edge collections), which repair
				// would then "fix" and immediately recreate as dangling
				// again on every subsequent run, forever.
				logger.Sugar().Warnf("Failed to upsert purl document %q for CVE %s, skipping edge: %v", basePurl, cveID, err)
				continue
			}
		}

		ranges, _ := affMap["ranges"].([]interface{})
		if len(ranges) == 0 {
			continue
		}

		// An entry with any ECOSYSTEM range is validated precisely in Go for
		// all of its ranges, so none of its edges may carry numeric parts.
		hasEcosystemRange := false
		for _, rangeItem := range ranges {
			if rm, ok := rangeItem.(map[string]interface{}); ok && rm["type"] == "ECOSYSTEM" {
				hasEcosystemRange = true
				break
			}
		}

		for _, rangeItem := range ranges {
			rangeMap, ok := rangeItem.(map[string]interface{})
			if !ok {
				continue
			}

			rangeType, _ := rangeMap["type"].(string)

			// Only process SEMVER and ECOSYSTEM ranges — GIT ranges use commit
			// SHAs which cannot be used for version matching
			if rangeType != "SEMVER" && rangeType != "ECOSYSTEM" {
				continue
			}

			events, _ := rangeMap["events"].([]interface{})

			var introduced, fixed, lastAffected string
			for _, eventItem := range events {
				eventMap, ok := eventItem.(map[string]interface{})
				if !ok {
					continue
				}
				if v, ok := eventMap["introduced"].(string); ok {
					introduced = v
				}
				if v, ok := eventMap["fixed"].(string); ok {
					fixed = v
				}
				if v, ok := eventMap["last_affected"].(string); ok {
					lastAffected = v
				}
			}

			if introduced == "" {
				introduced = "0"
			}

			introducedParsed := util.ParseSemanticVersion(introduced)
			fixedParsed := util.ParseSemanticVersion(fixed)
			lastAffectedParsed := util.ParseSemanticVersion(lastAffected)

			edge := map[string]interface{}{
				"_from":         cveDocID,
				"_to":           purlDocID,
				"type":          rangeType,
				"introduced":    introduced,
				"fixed":         fixed,
				"last_affected": lastAffected,
			}

			if introducedParsed.Major != nil {
				edge["introduced_major"] = *introducedParsed.Major
			}
			if introducedParsed.Minor != nil {
				edge["introduced_minor"] = *introducedParsed.Minor
			}
			if introducedParsed.Patch != nil {
				edge["introduced_patch"] = *introducedParsed.Patch
			}
			if fixedParsed.Major != nil {
				edge["fixed_major"] = *fixedParsed.Major
			}
			if fixedParsed.Minor != nil {
				edge["fixed_minor"] = *fixedParsed.Minor
			}
			if fixedParsed.Patch != nil {
				edge["fixed_patch"] = *fixedParsed.Patch
			}
			if lastAffectedParsed.Major != nil {
				edge["last_affected_major"] = *lastAffectedParsed.Major
			}
			if lastAffectedParsed.Minor != nil {
				edge["last_affected_minor"] = *lastAffectedParsed.Minor
			}
			if lastAffectedParsed.Patch != nil {
				edge["last_affected_patch"] = *lastAffectedParsed.Patch
			}
			if hasEcosystemRange {
				// Explicit nulls (not omission): the upsert below merges into
				// an existing edge, and stale numbers would otherwise survive.
				for _, k := range edgeVersionKeys {
					edge[k] = nil
				}
			}

			// UPSERT instead of check-then-create: one round-trip instead
			// of two, and as a side benefit it now also updates the edge
			// if a re-modified CVE's SEMVER range changed (introduced/
			// fixed/last_affected) -- the previous check-then-create only
			// checked for _from/_to existence, so a changed range on an
			// already-processed CVE silently kept the stale edge forever.
			edgeKey := cveKey + "_" + purlKey
			edge["_key"] = edgeKey

			edgeUpsertQuery := `
				UPSERT { _key: @key }
				INSERT @doc
				UPDATE @doc
				IN cve2purl
			`
			if _, err := dbconn.Database.Query(ctx, edgeUpsertQuery, &arangodb.QueryOptions{
				BindVars: map[string]interface{}{
					"key": edgeKey,
					"doc": edge,
				},
			}); err != nil {
				logger.Sugar().Warnf("Failed to upsert cve2purl edge from %s to %s: %v", cveDocID, purlDocID, err)
			}
		}
	}

	return nil
}

// ============================================================================
// Release to CVE Materialized Edge Creation
// BACKEND CONSISTENCY: Matches restapi/modules/releases/handlers.go
// ============================================================================
func updateReleaseEdgesForCVE(ctx context.Context, cveKey string) error {
	cveID := "cve/" + cveKey

	cleanupQuery := `
		FOR edge IN release2cve 
			FILTER edge._to == @cveID 
			REMOVE edge IN release2cve
	`
	dbconn.Database.Query(ctx, cleanupQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveID": cveID,
		},
	})

	query := `
		FOR cve IN cve
			FILTER cve._key == @cveKey

			FOR purl, cveEdge IN 1..1 OUTBOUND cve cve2purl

				FOR sbom, sbomEdge IN 1..1 INBOUND purl sbom2purl

					FILTER (
						sbomEdge.version_major != null AND
						cveEdge.introduced_major != null AND
						(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
					) ? (
						(
							sbomEdge.version_major > cveEdge.introduced_major OR
							(
								sbomEdge.version_major == cveEdge.introduced_major AND
								sbomEdge.version_minor > cveEdge.introduced_minor
							) OR
							(
								sbomEdge.version_major == cveEdge.introduced_major AND
								sbomEdge.version_minor == cveEdge.introduced_minor AND
								sbomEdge.version_patch >= cveEdge.introduced_patch
							)
						)
						AND
						(
							cveEdge.fixed_major != null ? (
								sbomEdge.version_major < cveEdge.fixed_major OR
								(
									sbomEdge.version_major == cveEdge.fixed_major AND
									sbomEdge.version_minor < cveEdge.fixed_minor
								) OR
								(
									sbomEdge.version_major == cveEdge.fixed_major AND
									sbomEdge.version_minor == cveEdge.fixed_minor AND
									sbomEdge.version_patch < cveEdge.fixed_patch
								)
							) : (
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(
									sbomEdge.version_major == cveEdge.last_affected_major AND
									sbomEdge.version_minor < cveEdge.last_affected_minor
								) OR
								(
									sbomEdge.version_major == cveEdge.last_affected_major AND
									sbomEdge.version_minor == cveEdge.last_affected_minor AND
									sbomEdge.version_patch <= cveEdge.last_affected_patch
								)
							)
						)
					) : true

					FOR release, r2s IN 1..1 INBOUND sbom release2sbom
						RETURN {
							release_id: release._id,
							package_purl_full: sbomEdge.full_purl,
							package_purl_base: purl.purl,
							package_version: sbomEdge.version,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`

	cursor, err := dbconn.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveKey": cveKey,
		},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	type Candidate struct {
		ReleaseID       string `json:"release_id"`
		PackagePurlFull string `json:"package_purl_full"`
		PackagePurlBase string `json:"package_purl_base"`
		PackageVersion  string `json:"package_version"`
		NeedsValidation bool   `json:"needs_validation"`
	}

	var candidates []Candidate
	needsValidation := false

	for cursor.HasMore() {
		var cand Candidate
		if _, err := cursor.ReadDocument(ctx, &cand); err != nil {
			continue
		}
		candidates = append(candidates, cand)
		if cand.NeedsValidation {
			needsValidation = true
		}
	}

	var cveAffectedMap map[string][]models.Affected
	if needsValidation {
		cveAffectedMap, err = util.FetchCVEAffectedData(ctx, dbconn.Database, []string{cveKey})
		if err != nil {
			return err
		}
	}

	var edgesToInsert []map[string]interface{}
	seenInstances := make(map[string]bool)

	for _, cand := range candidates {
		instanceKey := cand.ReleaseID + ":" + cand.PackagePurlBase
		if seenInstances[instanceKey] {
			continue
		}

		if cand.NeedsValidation {
			affectedData := cveAffectedMap[cveKey]
			if len(affectedData) == 0 {
				// The version cannot be validated, so do not guess: linking
				// every installed version of the package would be a false
				// positive for most of them.
				continue
			}
			if len(affectedData) > 0 {
				matchFound := false
				for _, affected := range affectedData {
					affectedPurl := ""
					if affected.Package.Purl != "" {
						affectedPurl = affected.Package.Purl
					} else {
						ecosystem := string(affected.Package.Ecosystem)
						namespace := affected.Package.Name
						if strings.Contains(namespace, "/") {
							parts := strings.Split(namespace, "/")
							if len(parts) == 2 {
								namespace = parts[0]
							}
						}
						affectedPurl = util.GetBasePURLFromComponents(ecosystem, namespace, affected.Package.Name)
					}

					standardizedAffectedPurl, err := util.GetStandardBasePURL(affectedPurl)
					if err != nil {
						continue
					}

					if standardizedAffectedPurl == cand.PackagePurlBase {
						if util.IsVersionAffected(cand.PackageVersion, affected) {
							matchFound = true
							break
						}
					}
				}
				if !matchFound {
					continue
				}
			}
		}

		seenInstances[instanceKey] = true

		edgesToInsert = append(edgesToInsert, map[string]interface{}{
			"_from":           cand.ReleaseID,
			"_to":             cveID,
			"type":            "static_analysis",
			"package_purl":    cand.PackagePurlFull,
			"package_base":    cand.PackagePurlBase,
			"package_version": cand.PackageVersion,
			"created_at":      time.Now().UTC().Format(time.RFC3339),
		})
	}

	if len(edgesToInsert) > 0 {
		insertQuery := `
			FOR edge IN @edges 
				INSERT edge INTO release2cve
		`
		_, err := dbconn.Database.Query(ctx, insertQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"edges": edgesToInsert,
			},
		})
		return err
	}

	return nil
}

// ============================================================================
// Lifecycle Tracking Update
// ============================================================================

func updateLifecycleForNewCVEs(_ int) error {
	ctx := context.Background()

	// Get current state of all endpoints with their active releases
	// Uses DATE_ISO8601 for robust parsing of string-based synced_at timestamps
	endpointStateQuery := `
		FOR endpoint IN endpoint
			// Find latest sync event for this endpoint
			LET latestSync = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					SORT DATE_TIMESTAMP(sync.synced_at) DESC
					LIMIT 1
					RETURN sync
			)[0]
			
			FILTER latestSync != null
			
			// Get all releases at this sync timestamp (current state)
			LET activeReleases = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					FILTER sync.synced_at == latestSync.synced_at
					RETURN {
						name: sync.release_name,
						version: sync.release_version
					}
			)
			
			RETURN {
				endpoint_name: endpoint.name,
				releases: activeReleases,
				last_sync_time: DATE_ISO8601(latestSync.synced_at)
			}
	`

	cursor, err := dbconn.Database.Query(ctx, endpointStateQuery, nil)
	if err != nil {
		return err
	}
	defer cursor.Close()

	// Process each endpoint
	for cursor.HasMore() {
		var state struct {
			EndpointName string
			Releases     []ReleaseInfo
			LastSyncTime time.Time
		}
		if _, err := cursor.ReadDocument(ctx, &state); err != nil || state.LastSyncTime.IsZero() {
			continue
		}

		// Get all CVEs affecting these releases
		currentCVEs, _ := getCVEsForReleases(ctx, state.Releases)

		// Update lifecycle records for each CVE
		for _, cveInfo := range currentCVEs {
			// Check if CVE was disclosed after deployment
			disclosedAfter := !cveInfo.Published.IsZero() && cveInfo.Published.After(state.LastSyncTime)

			// Create or update lifecycle record
			// The lifecycle package handles normalization of state.LastSyncTime internally
			lifecycle.CreateOrUpdateLifecycleRecord(
				ctx,
				dbconn,
				state.EndpointName,
				cveInfo.ReleaseName,
				cveInfo.ReleaseVersion,
				cveInfo,
				state.LastSyncTime,
				disclosedAfter,
			)
		}
	}

	return nil
}

// ============================================================================
// Helper Types and Functions
// ============================================================================

type ReleaseInfo struct {
	Name    string
	Version string
}

// getCVEsForReleases retrieves all CVEs affecting the given releases
func getCVEsForReleases(ctx context.Context, releases []ReleaseInfo) (map[string]lifecycle.CVEInfo, error) {
	result := make(map[string]lifecycle.CVEInfo)

	for _, rel := range releases {
		// Query CVEs via materialized release2cve edges
		cveQuery := `
			FOR r IN release
				FILTER r.name == @name 
				   AND r.version == @version
				
				// Traverse release2cve materialized edges
				FOR cve, edge IN 1..1 OUTBOUND r release2cve
					RETURN {
						cve_id: cve.id,
						published: cve.published,
						package: edge.package_base,
						severity_rating: cve.database_specific.severity_rating,
						severity_score: cve.database_specific.cvss_base_score
					}
		`

		cursor, _ := dbconn.Database.Query(ctx, cveQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"name":    rel.Name,
				"version": rel.Version,
			},
		})

		for cursor.HasMore() {
			var v struct {
				CveID          string  `json:"cve_id"`
				Published      string  `json:"published"`
				Package        string  `json:"package"`
				SeverityRating string  `json:"severity_rating"`
				SeverityScore  float64 `json:"severity_score"`
			}

			if _, err := cursor.ReadDocument(ctx, &v); err == nil {
				pub, _ := time.Parse(time.RFC3339, v.Published)

				// Create unique key for deduplication
				key := fmt.Sprintf("%s:%s:%s", v.CveID, v.Package, rel.Name)

				result[key] = lifecycle.CVEInfo{
					CVEID:          v.CveID,
					Package:        v.Package,
					SeverityRating: v.SeverityRating,
					SeverityScore:  v.SeverityScore,
					Published:      pub,
					ReleaseName:    rel.Name,
					ReleaseVersion: rel.Version,
				}
			}
		}
		cursor.Close()
	}

	return result, nil
}

// ============================================================================
// Main Entry Point
// ============================================================================

func main() {
	LoadFromOSVDev()
}

func init() {
	http.DefaultClient.Timeout = 120 * time.Second
}
