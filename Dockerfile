# syntax=docker/dockerfile:1

FROM golang:1.24.3-alpine AS builder

ARG GOARCH=amd64
ARG GOOS=linux

WORKDIR /build

ADD . /build/

RUN mkdir /out

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod/ \
    GOARCH=${GOARCH} GOOS=${GOOS} CGO_ENABLED=0 go build -o /out/service ./cmd

FROM alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/service /app

ENTRYPOINT ["/app/service"]
