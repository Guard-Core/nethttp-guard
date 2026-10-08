---
name: nethttp-guard
description: Use when wiring guard-core-go security into a Go net/http service, or when working in github.com/rennf93/nethttp-guard: build the middleware with nethttp.New(engine, opts...), tune WithMaxBodyBytes (default 262144) and WithLogger, attach route identity with WithRouteID, understand requestShim adaptation of *http.Request to guardcore.Request including the bounded body prefix scan, idempotent Body(), and replay so handlers still receive the full stream, exact verdict translation, fail-closed 500 on engine malfunction, and Redis-backed integration tests via REDIS_HOST and go test -tags integration.
---

# nethttp-guard

net/http middleware adapter for [guard-core-go](https://github.com/Guard-Core/guard-core-go). Translates `*http.Request` into the guardcore request surface, runs the engine, and translates verdicts to exact HTTP responses. Contains no security logic itself. Module: `github.com/rennf93/nethttp-guard`, Go `1.25.0`, tag `v0.1.0`.

## Quick Reference

| Identifier | Kind | Notes |
| --- | --- | --- |
| `nethttp.New(engine, opts...)` | func | Returns `(func(http.Handler) http.Handler, error)`; errors on nil engine |
| `nethttp.WithMaxBodyBytes(n)` | Option | Bounds engine body scan; ignored when `n <= 0`; default 262144 |
| `nethttp.WithLogger(l)` | Option | Fail-closed logger; ignored when nil; default `log.Default()` |
| `nethttp.WithRouteID(ctx, id)` | func | Returns a context carrying the route ID for `engine.Routes` lookups |
| `nethttp.DefaultMaxBodyBytes` | const | `262144` bytes (256 KiB) |

Behavior contract: the engine sees at most `MaxBodyBytes` of the body prefix; payloads beyond the bound are not scanned; the handler still receives the full body via replay. A verdict short-circuits the handler. An engine error or panic produces a 500 via `engine.CreateErrorResponse(500, "Security check failed")`. On a clean pass the adapter adds no headers and does not mutate the request.

## Installation

```sh
go get github.com/rennf93/nethttp-guard@v1.1.0 github.com/rennf93/guard-core-go/v4@v4.0.5-0.20260926230539-e39ac203568b
```

The package name is `nethttp`, so import it with an alias:

```go
import (
    guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
    nethttp "github.com/rennf93/nethttp-guard"
)
```

## Setup

```go
cfg := guardcore.DefaultSecurityConfig()
engine, err := guardcore.NewEngine(cfg)
if err != nil { log.Fatal(err) }
if err := engine.Initialize(); err != nil { log.Fatal(err) }

guard, err := nethttp.New(engine) // or nethttp.New(engine, nethttp.WithMaxBodyBytes(65536))
if err != nil { log.Fatal(err) }

mux := http.NewServeMux()
mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
log.Fatal(http.ListenAndServe(":8080", guard(mux)))
```

`Initialize` is required by the core. Redis connectivity is a guard-core-go concern; this adapter never talks to Redis directly.

## nethttp.New

```go
func New(engine *guardcore.Engine, opts ...Option) (func(http.Handler) http.Handler, error)
```

- Rejects a nil engine with `errors.New("engine must not be nil")`.
- Returns a standard middleware value, so it composes with the stdlib mux, chi, httprouter, gorilla, and anything speaking `func(http.Handler) http.Handler`.
- The returned wrapper builds a `requestShim`, calls `engine.Check`, then either applies the verdict and returns, or calls `next.ServeHTTP(w, r)`.
- Engine calls are wrapped in a recover: a panic from `engine.Check` (for example inside a user `CustomRequestCheck`) becomes an error and takes the fail-closed path.

## Options: WithMaxBodyBytes and WithLogger

```go
func WithMaxBodyBytes(maxBodyBytes int64) Option
func WithLogger(logger *log.Logger) Option
```

- `WithMaxBodyBytes` sets the byte bound scanned by the engine. Non-positive values are ignored and the default `DefaultMaxBodyBytes` (262144) applies. The bound also caps `ReadBodyPrefix`.
- `WithLogger` replaces the logger used on engine malfunction. Nil is ignored; the default is `log.Default()`. The message logged is `guardcore nethttp: engine malfunction, failing closed: <err>`.
- Invalid option values never cause an error from `New`; they are silently ignored.

## WithRouteID and Route Matching

```go
func WithRouteID(ctx context.Context, routeID string) context.Context
```

- Stores the route ID under a private context key. `requestShim` copies it to `guardcore.RequestState.GuardRouteID`.
- Route policy itself lives in the core: register with `engine.Routes.Register("name", func(rc *guardcore.RouteConfig) { rc.BypassedChecks = []string{"all"} })`, then attach the matching ID with `r.WithContext(nethttp.WithRouteID(r.Context(), "name"))`.
- Without a route ID in context the request is evaluated under default policy.

## Request Adaptation: requestShim and Body Replay

`requestShim` implements `guardcore.Request` and is the whole adaptation surface.

- `URLPath`, `URLScheme` (https when `req.TLS != nil`), `URLFull`, `URLReplaceScheme`, `Method` (uppercased, defaults to GET), `ClientHost` (via `net.SplitHostPort` on `RemoteAddr`).
- `Headers`: first value per header name only, plus an explicit `Host` from `req.Host`.
- `QueryParams`: first parsed value per key.
- `Body()` returns the cached prefix (bounded by `MaxBodyBytes`) and is idempotent.
- `ReadBodyPrefix(maxBytes)` extends the cache contiguously up to the bound; negative values clamp to 0, values above the bound clamp to `MaxBodyBytes`.
- `newRequestShim` replaces `r.Body` with a `replayBody`. Reads first return bytes the engine consumed from the cache, then stream the untouched remainder from the source. `Close` closes the original body.

## Footguns

- Import path and package name differ: `nethttp "github.com/rennf93/nethttp-guard"`.
- The engine only scans the first `MaxBodyBytes` bytes. A malicious marker beyond the bound is not detected and the request passes; verify bounds when a route accepts large payloads.
- `WithMaxBodyBytes(-1)` and `WithLogger(nil)` are silently ignored, not errors. Guard against typos that drop real configuration.
- Integration tests SKIP when `REDIS_HOST` is unset. `go test -tags integration ./...` can look green while Redis-backed coverage never ran.
- A panic inside a core custom check is converted to a 500. That is intentional fail-closed behavior, not a crash.
- Verdict headers, status, and body come from the core verbatim. Do not add or rewrite response headers in this adapter.
- Do not push to `main` (protected) and do not push `v*` tags; a tag push triggers the Release Gate workflow.

## Related Projects

- [guard-core-go](https://github.com/Guard-Core/guard-core-go): the engine this adapter wraps. All detection, rate limiting, bans, configuration, and Redis integration live there; import it as `guardcore "github.com/rennf93/guard-core-go/v4/guardcore"`.
