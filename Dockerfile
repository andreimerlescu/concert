# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27
ARG GOFIPS140=off

FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG GOFIPS140

RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOFIPS140=${GOFIPS140} \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/concert .

# Minimal, non-root, distroless runtime image (no shell, no package manager).
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="Concert" \
      org.opencontainers.image.description="Enterprise FIFO Waiting Room Reverse Proxy" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/concert /usr/local/bin/concert

EXPOSE 8080 8081
VOLUME ["/var/lib/concert/data"]

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/concert"]
