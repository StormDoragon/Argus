# Offline Vendoring Guide (Argus)

Use this when CI/build hosts cannot reach Go module mirrors or GitHub directly.

## Why this exists

Some networks block `proxy.golang.org`, `goproxy` mirrors, and/or direct GitHub module fetches. In that case `go mod tidy` fails and `go.sum` cannot be generated in CI.

Vendoring dependencies on an unrestricted machine makes builds deterministic and offline-capable.

## One-time prep on an unrestricted machine

From repo root:

```bash
# API module
cd api
go mod tidy
go mod vendor
cd ..

# Worker module
cd worker
go mod tidy
go mod vendor
cd ..
```

Then commit all of:
- `api/go.sum`
- `api/vendor/`
- `worker/go.sum`
- `worker/vendor/`

## Build/test in restricted environments

Use vendor mode explicitly:

```bash
cd api
go build -mod=vendor ./...
go test -mod=vendor ./...

cd ../worker
go build -mod=vendor ./...
go test -mod=vendor ./...
```

If needed for maintenance in blocked networks:

```bash
go mod tidy -mod=vendor
```

## Docker note

If your Docker build also runs in restricted egress, keep vendor directories in context and build with `-mod=vendor` where applicable.

## Validation checklist

- `api/go.sum` exists
- `worker/go.sum` exists
- `api/vendor/` exists
- `worker/vendor/` exists
- `go test -mod=vendor ./...` passes in both modules
