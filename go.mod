module github.com/ortelius/osv

go 1.27.1

require (
	github.com/arangodb/go-driver/v2 v2.4.1
	github.com/google/osv-scanner v1.9.2
	github.com/ortelius/ortelius/v12 v12.0.541
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/kkdai/maglev v0.2.0 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

// Pinned to match helm.sh/helm/v4 v4.2.4's own go.mod exactly. Helm's SDK
// is not independently version-compatible with arbitrary k8s.io/* releases
// -- without these pins, `go mod tidy` has no other constraint on these
// modules anywhere in this graph and will select @latest, which can pull in
// a k8s.io/apimachinery built against a different major version of
// sigs.k8s.io/structured-merge-diff than the rest of the resolved k8s.io/*
// family expects, breaking compilation. Bump these only in lockstep with
// the helm.sh/helm/v4 version above.
require (
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/aquasecurity/go-npm-version v0.0.2 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.1 // indirect
	github.com/aquasecurity/go-version v0.0.1 // indirect
	github.com/arangodb/go-velocypack v0.0.0-20200318135517-5af53c29c67e // indirect
	github.com/goccy/go-yaml v1.19.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/package-url/packageurl-go v0.1.7 // indirect
	github.com/pandatix/go-cvss v0.6.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

// Plain `require` above is only a floor under Go's MVS -- something else in
// the build graph (transitively, possibly several hops deep) can want a
// different k8s.io/apimachinery than v0.36.1, and MVS always selects the
// maximum version requested by anything in the graph. That skew is exactly
// what produces errors like "sigs.k8s.io/structured-merge-diff/vN ... as
// ... vM" -- two incompatible major versions of the same module pulled in
// by two different resolved k8s.io/* versions. `replace` is unconditional
// and wins regardless of what else asks for a newer version, so it's the
// only reliable way to force the whole k8s.io/* + sigs.k8s.io/* family to
// the single consistent set helm.sh/helm/v4 v4.2.4 was actually built
// against. Unlike the v3 SDK, v4 moved from docker/docker-based oras-go v1
// to oras.land/oras-go/v2, so no docker/docker replace is needed here.
replace (
	k8s.io/api => k8s.io/api v0.36.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.36.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.36.1
	k8s.io/apiserver => k8s.io/apiserver v0.36.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.36.1
	k8s.io/client-go => k8s.io/client-go v0.36.1
	k8s.io/component-base => k8s.io/component-base v0.36.1
	k8s.io/klog/v2 => k8s.io/klog/v2 v2.140.0
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20260317180543-43fb72c5454a
	k8s.io/kubectl => k8s.io/kubectl v0.36.1
	k8s.io/utils => k8s.io/utils v0.0.0-20260210185600-b8788abfbbc2
	sigs.k8s.io/json => sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730
	sigs.k8s.io/kustomize/api => sigs.k8s.io/kustomize/api v0.21.1
	sigs.k8s.io/kustomize/kyaml => sigs.k8s.io/kustomize/kyaml v0.21.1
	sigs.k8s.io/structured-merge-diff/v6 => sigs.k8s.io/structured-merge-diff/v6 v6.3.2
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.6.0
)
