# nethttp-guard

`nethttp-guard` is the official `net/http` adapter for
[guard-core-go](https://github.com/Guard-Core/guard-core-go), the Go port of the
guard-core security engine. It wraps any `http.Handler` with the full engine
pipeline: penetration detection, rate limiting, IP banning, and verdict
responses.

All security logic lives in the engine; this package is a thin shim that
translates `*http.Request` into `guardcore.Request`, runs the engine, and
writes the block verdict when one arrives.

## Installation

```bash
go get github.com/rennf93/nethttp-guard@v1.1.0 github.com/rennf93/guard-core-go/v4@v4.0.5-0.20260926230539-e39ac203568b
```

Requires Go 1.25 or later.

## Quick start

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

## What the shim handles

- Client identity: `net.SplitHostPort` on `RemoteAddr`, with trusted-proxy
  resolution performed by the engine (`SecurityConfig.TrustedProxies`)
- Headers: first value per key, plus the `Host` header
- Body: the first `maxBodyBytes` bytes are shown to the engine, and the body
  is made replayable so your handler still receives it after inspection
- Route IDs: read from the request context (see [Usage](usage.md))
- Fail-closed: engine panics become `500` with a fixed, non-leaky message

See [Configuration](configuration.md) for engine tuning and the
[examples](https://github.com/Guard-Core/nethttp-guard/tree/main/examples) for
runnable apps.
