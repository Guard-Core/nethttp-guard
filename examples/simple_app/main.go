// Command simple_app is a minimal server guarded by nethttp-guard, the
// net/http adapter for the guard-core-go engine. It demonstrates the
// canonical adapter wiring:
//
//	SecurityConfig -> NewEngine -> Initialize -> nethttp.New -> guard(mux)
//
// For a production-style layout (multi-stage Docker, nginx, route registry,
// admin routes), see ../advanced_app.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
	nethttp "github.com/rennf93/nethttp-guard"
)

func main() {
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		// Rate limiting: global 30 req/60s per client, with a strict
		// per-endpoint override used by the demo and the live smoke test.
		c.EnableRateLimiting = true
		c.RateLimit = 30
		c.RateLimitWindow = 60
		c.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
			"/rate/strict": {Requests: 1, Window: 10},
		}

		// IP banning: 5 violations in the window earn a 5 minute ban.
		c.EnableIPBanning = true
		c.AutoBanThreshold = 5
		c.AutoBanDuration = 300

		// Penetration detection: all categories, default thresholds.
		c.EnablePenetrationDetection = true

		// The Python engine automatically skips ssrf scanning for address
		// headers (host, x-forwarded-for, x-real-ip, ...). The Go engine
		// does not apply that built-in exclusion yet, so mirror it here;
		// otherwise a plain "Host: localhost" request is flagged as ssrf.
		c.ExcludedDetectionHeaders = map[string]bool{
			"host": true, "origin": true, "via": true,
			"x-forwarded-for": true, "x-forwarded-host": true,
			"x-real-ip": true, "x-client-ip": true,
			"x-cluster-client-ip": true, "cf-connecting-ip": true,
			"true-client-ip": true, "fly-client-ip": true,
			"x-envoy-external-address": true,
		}

		// Blocked user agents (regex patterns).
		c.BlockedUserAgents = []string{"badbot", "evil-crawler", "sqlmap"}

		// Custom block bodies, keyed by status code.
		c.CustomErrorResponses = map[int]string{
			403: "Blocked by nethttp-guard",
		}

		// Paths the pipeline never sees.
		c.ExcludePaths = []string{
			"/docs", "/redoc", "/openapi.json", "/favicon.ico", "/static", "/health",
		}

		// OnBlock is the engine's telemetry seam. Guard Agent integration
		// is not implemented in guard-core-go yet (setting EnableAgent
		// fails config validation), so wire the agent from here: forward
		// these payloads to guard-agent-go
		// (https://github.com/Guard-Core/guard-agent-go) once its event
		// pipeline accepts engine events.
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			log.Printf("guard blocked %s %s from %s via %s: %s",
				payload["method"], payload["path"], payload["client_ip"],
				payload["check_name"], payload["reason"])
		}

		// Redis: enabled when REDIS_URL is set (docker compose sets it to
		// redis://redis:6379). Without Redis the managers fall back to
		// in-process state, which is fine for a demo but not for replicas.
		if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
			c.EnableRedis = true
			c.RedisURL = redisURL
		} else {
			c.EnableRedis = false
		}
		if prefix := os.Getenv("REDIS_PREFIX"); prefix != "" {
			c.RedisPrefix = prefix
		}
	})
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	// Idempotent; connects Redis when enabled and primes cloud IP ranges.
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	// The adapter middleware: standard func(http.Handler) http.Handler.
	guard, err := nethttp.New(engine)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", info)
	mux.HandleFunc("/health", health)
	mux.HandleFunc("/echo", echo)
	mux.HandleFunc("/rate/strict", strict)
	mux.HandleFunc("/search", search)

	log.Println("simple_app listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", guard(mux)))
}

func info(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"app":"nethttp-guard simple_app","endpoints":` +
		`["/health","/echo (POST)","/rate/strict","/search?q="]}` + "\n"))
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

func echo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"echo":true}` + "\n"))
}

func strict(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"endpoint":"/rate/strict","limit":"1 request per 10 seconds"}` + "\n"))
}

func search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	encoded, err := json.Marshal(map[string]any{"query": q, "results": []string{}})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(encoded, '\n'))
}
