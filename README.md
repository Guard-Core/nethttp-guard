<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>net/http middleware adapter for [guard-core-go](https://github.com/Guard-Core/guard-core-go). Translates `*http.Request` into the guardcore request surface, runs the engine, and translates verdicts to exact HTTP responses. Works with the stdlib mux, chi, httprouter, gorilla, and anything speaking `func(http.Handler) http.Handler`.</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/nethttp-guard/releases">
        <img src="https://img.shields.io/github/v/tag/Guard-Core/nethttp-guard?label=release&color=0080ff" alt="Release tag">
    </a>
    <a href="https://guard-core.github.io/nethttp-guard/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/nethttp-guard/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/nethttp-guard/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/nethttp-guard/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/nethttp-guard/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/nethttp-guard/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/nethttp-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/nethttp-guard/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/nethttp-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/nethttp-guard/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/nethttp-guard/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/nethttp-guard?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/net/http-00ADD8.svg?style=flat" alt="net/http">
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/nethttp-guard/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

## Install

```
go get github.com/rennf93/nethttp-guard@v1.2.0 github.com/rennf93/guard-core-go/v4@v4.2.0
```

## Usage

```go
package main

import (
	"log"
	"net/http"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
	nethttp "github.com/rennf93/nethttp-guard"
)

func main() {
	cfg := guardcore.DefaultSecurityConfig()
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatal(err)
	}

	guard, err := nethttp.New(engine)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Fatal(http.ListenAndServe(":8080", guard(mux)))
}
```

Options: `nethttp.WithMaxBodyBytes(n)` bounds the body bytes the engine scans (default 262144), `nethttp.WithLogger(l)` swaps the fail-closed logger. Route-level configuration uses `engine.Routes.Register` plus `nethttp.WithRouteID(ctx, id)` on the request context.

Every engine `SecurityConfig` field is reachable through this adapter: global tuning (behavior rules with `BehaviorScanResponseBody` and the inspect-bytes budget, the geo lifecycle with `IPInfoToken`/`OnGeoEvent`, CORS, security headers, custom error bodies) goes through the `SecurityConfig` you hand to `guardcore.NewEngine`, per-route detection exclusions and per-route behavior/IP rules through `engine.Routes.Register`. On every pass-through response the adapter merges `Engine.ResponseHeaders()` with `Engine.CORSResponseHeaders(req)` and reports the response (status plus the leading inspect-budget bytes of the body when `BehaviorScanResponseBody` is on) to `Engine.ProcessResponse` for the behavioral return rules. See [docs/configuration.md](docs/configuration.md).

Engine malfunctions fail closed with a 500. Detection covers at most the first `MaxBodyBytes` of the body; payloads beyond the bound are not scanned, and the full body still reaches your handler untouched.

## Development

The middleware consumes the core as a normal module dependency, currently pinned to the guard-core-go master surface (`v4.0.5-0.20260926230539-e39ac203568b`, the behavior-rules / geo-lifecycle / route-detection-exclusions wave); no `replace` directive is used or needed. For cross-repo work on the core itself, add a temporary local `replace` line in your own checkout and drop it before committing.

Integration tests run against real Redis:

```
REDIS_HOST=127.0.0.1 go test -tags integration ./...
```

## License

MIT
