# Run restate-server
restate-server:
    restate-server

run env *flags:
    #!/usr/bin/env bash
    set -euo pipefail

    if [[ "{{ env }}" = "staging" ]]; then
        export http_proxy="http://proxy-to-cluster-stag:8080"

        go run ./cmd \
          {{ flags }}
    else
        export http_proxy="http://proxy-to-cluster:8080"

        go run ./cmd {{ env }}
    fi

# Register with Restate
register:
    restate deployments register --force --yes http://localhost:9080

build:
    goreleaser build --snapshot --single-target --clean -o bin/restate-allocators

# Run tests
test:
    go test ./...

# Clean
[confirm]
clean:
    rm -rf restate-data/
