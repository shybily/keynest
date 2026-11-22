FROM golang:1.27-alpine AS builder

ARG GOPROXY=https://proxy.golang.org,direct
ARG VERSION=0.3.2
ENV GOPROXY=${GOPROXY}

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X github.com/shybily/keynest/web.Version=${VERSION}" -o /out/keynest ./cmd/keynest

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 keynest \
    && adduser -S -D -H -u 10001 -G keynest keynest

COPY --from=builder /out/keynest /usr/local/bin/keynest

ENV KEYNEST_ADDR=:8080 \
    KEYNEST_DB=/var/lib/keynest/keynest.db

WORKDIR /var/lib/keynest
RUN chown 10001:10001 /var/lib/keynest
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD wget -q --spider -T 2 http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/keynest"]
