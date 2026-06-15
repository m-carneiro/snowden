<div align="center">

# 🕵️ Snowden

**A lightweight Go proxy for the NVD (NIST National Vulnerability Database).**

Query CVEs and CWEs through a clean REST API — no API quirks, no NVD response noise.

[![Go](https://img.shields.io/badge/Go-1.21-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Router](https://img.shields.io/badge/router-gorilla%2Fmux-success)](https://github.com/gorilla/mux)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)

</div>

---

## ✨ Features

- 🔎 **Lookup by CVE** — fetch full vulnerability detail by CVE id
- 🧬 **Lookup by CWE** — fetch the matching vulnerability for a weakness id
- ❤️ **Health endpoint** — trivial liveness probe for k8s / load balancers
- ⏱️ **Timeout-safe** — upstream NVD calls bounded at 10s, no hung requests
- 📝 **Request logging** — every call logged with remote addr, method, proto, path
- 🧪 **Tested** — 15 tests across model, client, and API layers

## 🏗️ Architecture

```
main.go ──▶ api.Server (gorilla/mux)
                │
                ├─ GET /api/v1/health
                ├─ GET /api/v1/vulnerability/cve?id=
                └─ GET /api/v1/vulnerability/cwe?id=
                          │
                          ▼
                   client (NVD proxy) ──HTTP──▶ NVD API
                          │
                          ▼
                   client/model (typed structs)
```

| Layer | Path | Responsibility |
|-------|------|----------------|
| Entry | `main.go` | Load env, wire & run server |
| API | `api/` | Routing, handlers, JSON write, error wrapping |
| Client | `client/` | NVD HTTP calls, unmarshal, map to model |
| Model | `client/model/` | NVD response structs |
| Config | `config/` | `.env` loading, request log middleware |

## 🚀 Quickstart

```bash
# 1. Configure
echo 'NVD_URL=https://services.nvd.nist.gov/rest/json/cves/2.0' > .env

# 2. Run
make run          # builds to bin/snowden and starts it

# 3. Hit it
curl 'http://localhost:80/api/v1/health'
curl 'http://localhost:80/api/v1/vulnerability/cve?id=CVE-2024-1234'
curl 'http://localhost:80/api/v1/vulnerability/cwe?id=CWE-79'
```

> **Note:** port `:80` needs root. Override with `PORT` (see below).

## ⚙️ Configuration

| Var | Required | Default | Description |
|-----|----------|---------|-------------|
| `NVD_URL` | ✅ | — | Base URL of the NVD endpoint to proxy |
| `PORT` | ❌ | `:80` | Listen address (e.g. `:8080`) |

Env is read from a `.env` file if present, otherwise from the process environment — container-friendly.

```bash
PORT=:8080 make run
```

## 📡 API

### `GET /api/v1/health`
```json
{ "status": "UP" }
```

### `GET /api/v1/vulnerability/cve?id={CVE_ID}`
Returns a **list** of matching vulnerabilities.

```bash
curl 'http://localhost:8080/api/v1/vulnerability/cve?id=CVE-2024-1234'
```

### `GET /api/v1/vulnerability/cwe?id={CWE_ID}`
Returns the **first** matching vulnerability for the weakness.

```bash
curl 'http://localhost:8080/api/v1/vulnerability/cwe?id=CWE-79'
```

### Errors
Missing id, no result, or upstream failure → `400` with:
```json
{ "error": "cveId is required" }
```

## 🛠️ Development

```bash
make build        # compile to bin/snowden
make run          # build + run
make test         # go test -v ./...
go vet ./...      # static checks
```

## 🧪 Tests

15 tests, 5 packages. Upstream NVD is mocked with `httptest` — no network needed.

| Package | Covers |
|---------|--------|
| `client/model` | CVE/CWE marshalling (empty, passthrough) |
| `client` | NVD client: success, empty id, empty result, bad JSON |
| `api` | health, vulnerability controllers, error wrapper |

```bash
make test
```

## 📁 Project layout

```
snowden/
├── main.go                          # entrypoint
├── api/
│   ├── server.go                    # router, JSON helpers, error wrapper
│   ├── health.go                    # health handler
│   └── vulnerability-controller.go  # CVE/CWE handlers
├── client/
│   ├── nvd-client.go                # NVD HTTP calls
│   └── model/                       # response structs + marshalling
├── config/
│   ├── env.go                       # .env loading
│   └── request-log-filter.go        # request logging middleware
└── Makefile
```

## License

MIT.
