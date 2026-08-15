# syntax=docker/dockerfile:1.12
FROM golang:1.27rc2-bookworm AS build
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
COPY --from=build /out/pg-kms-gateway /usr/local/bin/pg-kms-gateway
USER 65532:65532
EXPOSE 6432 8080
ENTRYPOINT ["/usr/local/bin/pg-kms-gateway"]
CMD ["serve", "--config", "/etc/pgkms/config.yaml"]
