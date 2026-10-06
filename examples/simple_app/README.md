# nethttp-guard simple app

A minimal `net/http` server guarded by nethttp-guard, in a single `main.go`.
It shows the canonical adapter wiring and the security knobs that matter.

For a production-style layout (multi-stage Docker, nginx, route registry,
admin routes), see [`../advanced_app`](../advanced_app).

## Run it

With Docker Compose (recommended, includes Redis):

```bash
cd examples/simple_app
docker compose up --build
```

Or with the Go toolchain (in-process state, no Redis needed):

```bash
go run ./examples/simple_app
```

## Endpoints

| Endpoint | What it demonstrates |
|---|---|
| `GET /` | API info; passes the guard |
| `GET /health` | Liveness probe; excluded from the pipeline via `ExcludePaths` |
| `POST /echo` | Body-bearing request through detection |
| `GET /rate/strict` | Per-endpoint rate limit: 1 request per 10 seconds (`EndpointRateLimits`) |
| `GET /search?q=...` | Query parameter scanning; XSS payloads are blocked as suspicious activity |

## Try the security behavior

```bash
# Allowed
curl -i http://localhost:8080/

# Blocked by penetration detection (400, suspicious activity)
curl -i -G http://localhost:8080/search --data-urlencode 'q=<script>alert(1)</script>'

# Rate limited: the second request within 10 seconds returns 429
curl -i http://localhost:8080/rate/strict
curl -i http://localhost:8080/rate/strict

# Auto-banned: after AutoBanThreshold (5) violations the IP is banned and
# every verdict carries the custom 403 body
curl -i http://localhost:8080/
```

## Configuration knobs demonstrated

Inline comments in `main.go` walk through every knob used:

- Global rate limiting (`RateLimit`, `RateLimitWindow`) and per-endpoint
  overrides (`EndpointRateLimits`)
- Auto-banning (`AutoBanThreshold`, `AutoBanDuration`)
- Penetration detection with all categories enabled
- Proxy trust (`TRUSTED_PROXIES`): the engine resolves the real client from
  X-Forwarded-For behind a declared proxy, so bans/rate limits/geo key on the
  client instead of the proxy
- Address-header handling (built in: the engine skips only the ssrf category
  for address-carrying headers, other categories still scan them)
- Blocked user agents (regex patterns)
- `CustomErrorResponses` for consistent block bodies
- `ExcludePaths` for health and docs routes
- Structured logging: `LOG_FORMAT=json` plus optional `LOG_FILE` switches the
  engine and adapter log streams to JSON records
- Redis via `REDIS_URL` / `REDIS_PREFIX` (compose wires Redis in; without it
  the managers fall back to in-process state)
- Agent telemetry: `EnableAgent` + `AgentHandler` (set `AGENT_OTLP_ENDPOINT`
  to install an OTLP sink through `CompositeAgentHandler`; any
  `guardcore.AgentHandler` plugs in, and
  [guard-agent-go](https://github.com/rennf93/guard-agent-go) bridges via
  `guardcore.AgentHandlerFunc`). `OnBlock` is the separate local blocking hook.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REDIS_URL` | (unset; Redis disabled) | When set, bans and rate limits are shared through Redis |
| `REDIS_PREFIX` | `nethttp_guard:` | Redis key prefix |
| `TRUSTED_PROXIES` | (unset; no proxy trust) | Comma-separated trusted proxy IPs/CIDRs; enables the X-Forwarded-For chain walk |
| `LOG_FORMAT` | `text` | `json` switches the engine and adapter log streams to JSON records |
| `LOG_FILE` | (unset; stderr only) | When set, log records also append to this file |
| `AGENT_OTLP_ENDPOINT` | (unset; agentless) | When set, installs an OTLP agent sink (`EnableAgent` + `AgentHandler`) |
