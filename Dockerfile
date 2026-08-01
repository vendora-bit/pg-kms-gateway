# syntax=docker/dockerfile:1.12
FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/pg-kms-gateway ./cmd/pg-kms-gateway

FROM gcr.io/distroless/cc-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="pg-kms-gateway" \
      org.opencontainers.image.description="Policy-driven PostgreSQL field encryption gateway backed by KMS" \
      org.opencontainers.image.source="https://github.com/vendora-bit/pg-kms-gateway" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/pg-kms-gateway /usr/local/bin/pg-kms-gateway
USER 65532:65532
EXPOSE 6432 8080
ENTRYPOINT ["/usr/local/bin/pg-kms-gateway"]
CMD ["serve", "--config", "/etc/pgkms/config.yaml"]
