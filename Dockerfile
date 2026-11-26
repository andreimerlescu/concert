# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27
ARG GOFIPS140=off
ARG VERSION=v0.3.0

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src
ENV GOTOOLCHAIN=auto

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY VERSION LICENSE version.go ./
COPY cmd/concert ./cmd/concert
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ARG GOFIPS140

RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH:-amd64} \
    GOFIPS140=${GOFIPS140} \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/concert ./cmd/concert && \
    mkdir -p /rootfs/var/lib/concert/data /rootfs/var/lib/concert/acme /rootfs/etc/concert

# Minimal, non-root, distroless runtime image (no shell, no package manager).
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=v0.3.0

LABEL org.opencontainers.image.title="concert" \
      org.opencontainers.image.description="FIFO Waiting Room Reverse Proxy and Front-Door Server (Core Edition)" \
      org.opencontainers.image.source="https://github.com/andreimerlescu/concert" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=builder /out/concert /usr/local/bin/concert
COPY --from=builder --chown=65532:65532 /rootfs/var/lib/concert /var/lib/concert
COPY --from=builder --chown=65532:65532 /rootfs/etc/concert /etc/concert

EXPOSE 80/tcp 443/tcp 443/udp 8080/tcp 8081/tcp
VOLUME ["/var/lib/concert/data", "/var/lib/concert/acme"]

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/concert"]
