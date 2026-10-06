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
	"strings"

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

		// Proxy trust: when this app sits behind a reverse proxy or load
		// balancer, declare it here. The engine then resolves the real
		// client from X-Forwarded-For (walking the chain right-to-left
		// under TrustedProxyDepth), so rate limits, bans, and geo rules
		// key on the forwarded client instead of the proxy address.
		//
		// Note on address headers and detection: the engine already
		// routes proxy identity/forwarding headers (host, origin, via,
		// x-forwarded-for, x-real-ip, cf-connecting-ip, ...) through its
		// built-in exclusion set and skips only the ssrf category for
		// address-carrying headers - every other category still scans
		// them (guardcore/headerexclusions.go). Do NOT hand-add these
		// headers to ExcludedDetectionHeaders: full exclusion masks real
		// attacks (XSS, SQLi, recon payloads) smuggled in those headers.
		if proxies := os.Getenv("TRUSTED_PROXIES"); proxies != "" {
			c.TrustedProxies = strings.Split(proxies, ",")
			c.TrustXForwardedProto = true
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

		// Structured logging: LOG_FORMAT=json (and optionally LOG_FILE)
		// switches the engine's log stream to JSON records; the adapter
		// below shares the stream through WithLogger.
		if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
			c.LogFormat = logFormat
		}
		if logFile := os.Getenv("LOG_FILE"); logFile != "" {
			c.LogFile = logFile
		}

		// Agent telemetry: EnableAgent works - the engine validates it
		// and installs the event stream whenever AgentHandler is set.
		// Any guardcore.AgentHandler plugs in directly; CompositeAgent
		// Handler fans one stream out to several sinks (OTLP, Logfire,
		// your own), and guard-agent-go bridges through
		// guardcore.AgentHandlerFunc (its SendEvent carries a context
		// and its own event model). OnBlock below is the separate local
		// blocking hook, independent of the agent stream.
		if agentEndpoint := os.Getenv("AGENT_OTLP_ENDPOINT"); agentEndpoint != "" {
			c.EnableAgent = true
			c.AgentHandler = guardcore.NewCompositeAgentHandler([]guardcore.AgentHandler{
				guardcore.NewOtelHandler(guardcore.OtelConfig{
					ServiceName:      "nethttp-guard-simple-app",
					ExporterEndpoint: agentEndpoint,
				}),
			}, nil)
		}

		// OnBlock is the engine's local blocking hook (payload fields:
		// check_name, reason, trigger_info, client_ip, path, method,
		// status_code, passive_mode). The agent event stream above is
		// the telemetry seam; this hook is for local reactions.
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
	// WebSocket upgrades are guarded by default (blocked handshakes
	// answer the engine verdict through the reference's close shapes);
	// WithWebSocketGuard(false) opts out. WithLogger shares the engine's
	// structured stream with the adapter's own lines: SetupCustomLogging
	// installs whatever the config switch selected (text or JSON) and
	// returns the logger.
	var opts []nethttp.Option
	if cfg.LogFormat == "json" || cfg.LogFile != "" {
		opts = append(opts, nethttp.WithLogger(guardcore.SetupCustomLogging(cfg.LogFile, cfg.LogFormat)))
	}
	guard, err := nethttp.New(engine, opts...)
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
