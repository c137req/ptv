# ptv api documentation

the ptv api wraps the same module registry and parse/render pipeline as the cli. all 83 formats are available via path-based routing — adding new format modules requires zero route changes.

## daemon management

```bash
ptv -daemon start [-v]              # start, auto-generates api key
ptv -daemon start -api-key <key>    # start with explicit key
ptv -daemon stop                    # graceful shutdown (30s drain)
ptv -daemon status                  # check if running
```

the server runs in the foreground. use systemd, nohup, or `&` to background it.

### api key

the key is resolved in order:

1. `-api-key` flag
2. `PTV_API_KEY` environment variable
3. auto-generated (16 chars, mixed latin/cyrillic/digits)

the generated key is printed to stderr on start. it's ephemeral — regenerated each start unless explicitly provided.

## configuration

| flag | default | description |
|------|---------|-------------|
| `-daemon` | | daemon control: `start`, `stop`, `status` |
| `-bind` | `0.0.0.0:0474` | api bind address |
| `-random-port` | `false` | use os-assigned random port |
| `-api-key` | auto | api key (or `PTV_API_KEY` env var) |
| `-max-body` | `10MB` | maximum request body size |
| `-rate-limit` | `60` | requests per minute per ip |
| `-cors-origin` | | allowed cors origin (empty = disabled) |
| `-tls-cert` | | tls certificate path |
| `-tls-key` | | tls private key path |
| `-pid-file` | `/tmp/ptv.pid` | daemon pid file path |
| `-timeout` | `30s` | per-request processing timeout |
| `-v` | `false` | verbose logging to stderr |

## routes

| method | path | auth | description |
|--------|------|------|-------------|
| `POST` | `/convert/{from}/{to}` | yes | convert data between formats |
| `GET` | `/formats` | yes | list available format modules |
| `GET` | `/health` | no | uptime and format count |
| `GET` | `/metrics` | yes | request stats and per-format usage |

authentication is via the `X-API-Key` header on all routes except `/health`.

## endpoints

### `POST /convert/{from}/{to}`

convert data from one format to another. format names are path variables matching the names from `ptv -formats`.

**request:**

```json
{
  "data": "<base64-encoded input>"
}
```

all data is base64-encoded because many formats are binary (parquet, bson, protobuf, etc.).

**response (success):**

```json
{
  "ok": true,
  "data": "<base64-encoded output>",
  "meta": {
    "source_format": "csv",
    "target_format": "json_flat",
    "record_count": 42,
    "parsed_at": "2026-02-09T12:00:00Z"
  }
}
```

**response (error):**

```json
{
  "ok": false,
  "error": {
    "code": "invalid_format",
    "message": "conversion failed"
  }
}
```

### `GET /formats`

list all registered format modules.

**response:**

```json
{
  "ok": true,
  "formats": ["access_log", "avro", "aws_credentials", "..."],
  "count": 83
}
```

### `GET /health`

unauthenticated health check.

**response:**

```json
{
  "ok": true,
  "count": 83,
  "uptime_seconds": 3600.5
}
```

### `GET /metrics`

request statistics and per-format usage.

**response:**

```json
{
  "ok": true,
  "uptime_seconds": 3600.5,
  "stats": {
    "total": 1500,
    "successful": 1420,
    "failed": 80,
    "rate_limited": 12,
    "auth_failures": 5,
    "avg_latency_ms": 45.2,
    "conversions": {
      "csv": {"from": 200, "to": 150},
      "json_flat": {"from": 300, "to": 400}
    }
  }
}
```

## error codes

| code | http status | meaning |
|------|-------------|---------|
| `bad_request` | 400 | malformed request body |
| `invalid_format` | 400 | unknown or invalid format name |
| `bad_data` | 400 | data field is not valid base64 |
| `empty_data` | 400 | data field is empty |
| `parse_error` | 422 | source format parser failed |
| `render_error` | 422 | target format renderer failed |
| `unauthorised` | 401 | missing or invalid api key |
| `rate_limited` | 429 | too many requests (includes `Retry-After: 60` header) |
| `forbidden` | 403 | request from non-internal ip |
| `internal_error` | 500 | unexpected server error |

error responses never expose internal details. parser/renderer errors are logged to stderr in verbose mode only.

## security

### internal-ip only

requests are accepted only from private and loopback source ips (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `::1`). checked via the actual tcp connection source (`r.RemoteAddr`), never headers. anything else gets a 403.

### constant-time authentication

api key comparison uses `crypto/subtle.ConstantTimeCompare` with length-padded inputs. no timing side-channels on key length or content.

### anti-enumeration

`POST /convert/{from}/{to}` returns identical errors for invalid format names and parse failures. both source and target module lookups always execute before checking either result. format names are validated against `^[a-z][a-z0-9_]{0,63}$` before registry lookup.

### rate limiting

per-ip sliding window rate limiter (in-memory). configurable via `-rate-limit` (default 60 rpm). `X-Forwarded-For` is intentionally not trusted. stale entries are pruned every 5 minutes.

### oom prevention

- `http.MaxBytesReader` enforces body limit at transport level
- `ReadTimeout` (10s) prevents slow request bodies
- `ReadHeaderTimeout` (5s) prevents slowloris attacks
- base64 decoding is bounded by the body limit

### server hardening

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'none'`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`
- `MaxHeaderBytes: 64KB`
- `IdleTimeout: 120s`
- panic recovery middleware catches handler panics and returns generic 500 responses

### tls

optional tls support via `-tls-cert` and `-tls-key` flags. when both are provided, the server uses `ServeTLS` instead of plain http.

## middleware chain

request processing order (outermost to innermost):

1. **recovery** — catch panics, return 500
2. **security headers** — set on all responses
3. **internal ip gate** — reject non-private source ips
4. **cors** — handle preflight (if configured)
5. **rate limit** — per-ip sliding window (before auth to limit brute force)
6. **body size limit** — reject oversized payloads early
7. **authentication** — constant-time api key check (skip for `/health`)
8. **timeout** — `context.WithTimeout` on request context
9. **logging** — verbose mode only, logs method/path/status/duration/ip

## examples

### start with defaults

```bash
ptv -daemon start -v
# [ptv] generated api key: фцqпqnтt9цюпгu9ф
# [ptv] listening on 0.0.0.0:0474
```

### start with custom config

```bash
ptv -daemon start \
  -bind 127.0.0.1:8080 \
  -api-key mysecretkey \
  -rate-limit 120 \
  -max-body 52428800 \
  -timeout 60s \
  -v
```

### start with random port

```bash
ptv -daemon start -random-port -v
# [ptv] listening on 0.0.0.0:46489
```

### start with tls

```bash
ptv -daemon start \
  -tls-cert /path/to/cert.pem \
  -tls-key /path/to/key.pem \
  -v
```

### convert csv to json

```bash
DATA=$(base64 -w0 < input.csv)
curl -X POST \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$DATA\"}" \
  http://localhost:0474/convert/csv/json_flat \
  | jq -r '.data' | base64 -d
```

### convert shadow to csv

```bash
DATA=$(base64 -w0 < /etc/shadow)
curl -X POST \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d "{\"data\":\"$DATA\"}" \
  http://localhost:0474/convert/shadow/csv \
  | jq -r '.data' | base64 -d
```

### list formats

```bash
curl -H "X-API-Key: <key>" http://localhost:0474/formats | jq
```

### check health

```bash
curl http://localhost:0474/health | jq
```

### view metrics

```bash
curl -H "X-API-Key: <key>" http://localhost:0474/metrics | jq
```

### stop the daemon

```bash
ptv -daemon stop
```

### using environment variable for api key

```bash
export PTV_API_KEY="mysecretkey"
ptv -daemon start -v
```
