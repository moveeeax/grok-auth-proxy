# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/grok-auth-proxy ./cmd/proxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget \
    && adduser -D -H -u 65532 nonroot

WORKDIR /app
COPY --from=builder /out/grok-auth-proxy /app/grok-auth-proxy

USER nonroot:nonroot
EXPOSE 8080

ENV GAP_SERVER_ADDR=:8080 \
    GAP_AUTH_FILE=/config/auth.json \
    GAP_DB_DSN=/data/proxy.db

VOLUME ["/config", "/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/app/grok-auth-proxy"]
