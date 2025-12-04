# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.24.3-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /build

ADD . /build/

RUN mkdir /out

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod/ \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -o /out/service ./cmd

FROM --platform=$TARGETPLATFORM alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/service /app

ENTRYPOINT ["/app/service"]
