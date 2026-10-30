# ---------- Build stage ----------
FROM public.ecr.aws/amazonlinux/amazonlinux:2027.0.20261026.1-minimal AS build

WORKDIR /app

RUN microdnf install -y \
      git \
      golang

COPY . /app

RUN go mod tidy && \
    go build -o main . 

# ---------- Runtime stage ----------
FROM public.ecr.aws/amazonlinux/amazonlinux:2027.0.20261026.1-minimal

WORKDIR /app

ENV CDXGEN_VERSION=v13.5.0

RUN microdnf update -y && \
    microdnf install -y \
      ca-certificates \
      git \
    && microdnf clean all \
    && rm -rf /var/cache/dnf /var/cache/yum

RUN ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/') && \
    ASSET="cdxgen-linux-${ARCH}" && \
    BASE_URL="https://github.com/cdxgen/cdxgen/releases/download/${CDXGEN_VERSION}" && \
    cd /tmp && \
    curl -fsSLO "${BASE_URL}/${ASSET}" && \
    curl -fsSLO "${BASE_URL}/${ASSET}.sha256" && \
    sha256sum -c "${ASSET}.sha256" && \
    install -m 0755 "${ASSET}" /usr/local/bin/cdxgen && \
    cdxgen --version && \
    rm -rf "${ASSET}" "${ASSET}.sha256" /tmp/caxa

COPY --from=build /app/main /app/main

ENV ARANGO_HOST=localhost
ENV ARANGO_USER=root
ENV ARANGO_PASS=rootpassword
ENV ARANGO_PORT=8529
ENV GITHUB_APP_ID=2695570
ENV GITHUB_CLIENT_ID=Iv23liVE3QJYlS6BGQRa

EXPOSE 8080

ENTRYPOINT ["/app/main", "process-workflow"]