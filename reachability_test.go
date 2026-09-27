package nethttp

// Reachability tests: every engine SecurityConfig surface must be
// configurable through this adapter's public API and observable in the
// middleware behavior. Configure via guardcore.SecurityConfig (the adapter's
// config idiom: the user builds the engine and hands it to New), attach
// route IDs via WithRouteID, and observe the verdicts and headers the
// adapter produces.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

type fakeCountryResolver struct {
	country string
}

func (f fakeCountryResolver) GetCountry(string) (string, bool) {
	if f.country == "" {
		return "", false
	}
	return f.country, true
}

// serveWithRouteID runs a request through the guard with an engine route ID
// attached via WithRouteID, the net/http adapter's route-ID path.
func serveWithRouteID(t *testing.T, engine *guardcore.Engine, routeID, target string, handlerBody ...string) *httptest.ResponseRecorder {
	t.Helper()
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "handler-body"
		if len(handlerBody) > 0 {
			body = handlerBody[0]
		}
		_, _ = w.Write([]byte(body))
	})
	r := httptest.NewRequest("GET", target, nil)
	if routeID != "" {
		r = r.WithContext(WithRouteID(r.Context(), routeID))
	}
	rec := httptest.NewRecorder()
	guard(next).ServeHTTP(rec, r)
	return rec
}

// Global behavior rules: a route usage rule (route_config.behavior_rules)
// bans the client once the threshold trips, and the adapter surfaces the
// engine's 403 "IP address banned" verdict on the next request.
func TestReachabilityRouteBehaviorUsageRuleBans(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.EnableRateLimiting = false
		c.GlobalBehaviorRules = nil
	})
	engine.Routes.Register("limited", func(rc *guardcore.RouteConfig) {
		rc.BehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "usage", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	// Two requests trip threshold 1 engine-side (strictly greater): both
	// pass, the ban lands on the usage rule, and the next request is 403.
	for i := 0; i < 2; i++ {
		rec := serveWithRouteID(t, engine, "limited", "/api/data")
		if rec.Code != 200 {
			t.Fatalf("request %d must pass, got %d: %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := serveWithRouteID(t, engine, "limited", "/api/data")
	if rec.Code != 403 || strings.TrimSpace(rec.Body.String()) != "IP address banned" {
		t.Fatalf("usage-rule ban must answer 403 %q, got %d %q", "IP address banned", rec.Code, rec.Body.String())
	}
}

// Global return_pattern rules with behavior_scan_response_body enabled and a
// bounded inspect budget: the adapter captures the handler's response body
// prefix and hands it to Engine.ProcessResponse, the rule trips, and the
// client is banned for subsequent requests. A pattern placed beyond the
// inspect budget never matches.
func TestReachabilityGlobalReturnPatternBodyScan(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "leaked-secret", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	for i := 0; i < 2; i++ {
		rec := serveWithRouteID(t, engine, "", "/report", "report leaked-secret trailer")
		if rec.Code != 200 {
			t.Fatalf("request %d must pass, got %d", i+1, rec.Code)
		}
	}
	rec := serveWithRouteID(t, engine, "", "/report", "report leaked-secret trailer")
	if rec.Code != 403 || strings.TrimSpace(rec.Body.String()) != "IP address banned" {
		t.Fatalf("return-pattern ban must answer 403 %q, got %d %q", "IP address banned", rec.Code, rec.Body.String())
	}

	// Budget bound: the marker sits past the 1024-byte inspect budget, so
	// the rule can never match and the client is never banned.
	other := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "beyond-the-budget", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	guard, err := New(other)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	bigHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		big := make([]byte, 2048)
		for i := range big {
			big[i] = 'a'
		}
		copy(big[1500:], "beyond-the-budget")
		_, _ = w.Write(big)
	})
	for i := 0; i < 4; i++ {
		r := httptest.NewRequest("GET", "/report", nil)
		rec := httptest.NewRecorder()
		guard(bigHandler).ServeHTTP(rec, r)
		if rec.Code != 200 {
			t.Fatalf("pattern beyond the budget must never trip, got %d on request %d", rec.Code, i+1)
		}
	}
}

// status: return patterns work with the scan flag off: the adapter still
// reports the response status to Engine.ProcessResponse.
func TestReachabilityStatusReturnPatternWithoutScan(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = false
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "status:404", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	// The handler writes the 404 itself so the adapter observes the status
	// and body while the middleware still runs.
	missing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing"))
	})
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/missing", nil)
		rec := httptest.NewRecorder()
		guard(missing).ServeHTTP(rec, r)
		if rec.Code != 404 {
			t.Fatalf("request %d must answer 404, got %d", i+1, rec.Code)
		}
	}
	if !engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("two 404s over threshold 1 must ban the client through the adapter")
	}
}

// Per-route detection exclusions (the #28 surface): the excluded query
// parameter no longer reaches detection on the configured route, while the
// same payload is blocked everywhere else with the reference 400.
func TestReachabilityPerRouteDetectionExclusions(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.Routes.Register("open", func(rc *guardcore.RouteConfig) {
		rc.ExcludedDetectionParams = map[string]bool{"q": true}
	})
	rec := serveWithRouteID(t, engine, "open", "/search?q=<script>alert(1)</script>")
	if rec.Code != 200 {
		t.Fatalf("excluded param must pass on the configured route, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = serveWithRouteID(t, engine, "", "/search?q=<script>alert(1)</script>")
	if rec.Code != 400 || strings.TrimSpace(rec.Body.String()) != "Suspicious activity detected" {
		t.Fatalf("the same payload must be blocked off-route with 400 %q, got %d %q",
			"Suspicious activity detected", rec.Code, rec.Body.String())
	}
}

// Geo lifecycle: route country rules resolve through the configured
// GeoIPHandler, a blocked country answers the reference 403 "Forbidden", and
// the OnGeoEvent hook receives the country_blocked event with the reference
// fields.
func TestReachabilityGeoLifecycle(t *testing.T) {
	var events []guardcore.GeoEvent
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.GeoIPHandler = fakeCountryResolver{country: "CN"}
		c.OnGeoEvent = func(ev guardcore.GeoEvent) { events = append(events, ev) }
	})
	// Route-level country rules (the geo lifecycle's observable path for
	// country_blocked; the global country verdict blocks without emitting
	// the event in this port).
	engine.Routes.Register("geo", func(rc *guardcore.RouteConfig) {
		rc.BlockedCountries = []string{"CN"}
	})
	rec := serveWithRouteID(t, engine, "geo", "/download")
	if rec.Code != 403 || strings.TrimSpace(rec.Body.String()) != "Forbidden" {
		t.Fatalf("blocked country must answer 403 %q, got %d %q", "Forbidden", rec.Code, rec.Body.String())
	}
	// The route country deny emits country_blocked followed by the
	// decorator_violation access-denied event, both with the reference
	// fields.
	if len(events) != 2 {
		t.Fatalf("OnGeoEvent must receive country_blocked and decorator_violation, got %+v", events)
	}
	blocked, violation := events[0], events[1]
	if blocked.EventType != guardcore.EventCountryBlocked || blocked.Country != "CN" ||
		blocked.RuleType != "country_blacklist" || blocked.ActionTaken != "request_blocked" {
		t.Fatalf("country_blocked event fields mismatch, got %+v", blocked)
	}
	if violation.EventType != guardcore.EventDecoratorViolation || violation.Metadata["decorator_type"] != "block_countries" {
		t.Fatalf("decorator_violation event fields mismatch, got %+v", violation)
	}
}

// IPInfo lifecycle validation: a max-age without a token fails config
// construction (the adapter cannot be handed such an engine), and a valid
// token with max-age 0 falls back to the reference default of 86400.
func TestReachabilityIPInfoLifecycleConfig(t *testing.T) {
	if _, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.IPInfoMaxAge = 3600
	}); err == nil || !strings.Contains(err.Error(), "ipinfo_token") {
		t.Fatalf("max-age without token must fail config construction, got %v", err)
	}
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.IPInfoToken = "token"
	})
	if err != nil {
		t.Fatalf("token-only config must validate: %v", err)
	}
	if cfg.IPInfoMaxAge != guardcore.DefaultIPInfoMaxAge {
		t.Fatalf("max-age default must be %d, got %d", guardcore.DefaultIPInfoMaxAge, cfg.IPInfoMaxAge)
	}
}

// CORS: pass-through responses carry the CORS headers merged over the
// security-header set, and preflights are short-circuited by the engine
// through the adapter.
func TestReachabilityCORS(t *testing.T) {
	guard, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"https://app.example"}
		c.CORSAllowMethods = []string{"GET", "POST"}
	})
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	guard(okHandler).ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("pass-through must stay 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("pass-through must carry the CORS allow-origin header, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got == "" {
		t.Fatal("CORS headers must be merged over the security-header set, not replace it")
	}

	preflight := httptest.NewRequest("OPTIONS", "/api", nil)
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	guard(okHandler).ServeHTTP(rec, preflight)
	if rec.Code != 200 || rec.Body.String() != "OK" {
		t.Fatalf("allowed preflight must short-circuit 200 OK, got %d %q", rec.Code, rec.Body.String())
	}

	denied := httptest.NewRequest("OPTIONS", "/api", nil)
	denied.Header.Set("Origin", "https://evil.example")
	denied.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	guard(okHandler).ServeHTTP(rec, denied)
	if rec.Code != 400 || !strings.HasPrefix(rec.Body.String(), "Disallowed CORS:") {
		t.Fatalf("disallowed preflight must answer 400 Disallowed CORS, got %d %q", rec.Code, rec.Body.String())
	}
}

// Custom error bodies compose with the detection verdict: the configured
// 400 body replaces the default while the status code and the security
// headers stay engine-owned.
func TestReachabilityCustomErrorResponses(t *testing.T) {
	guard, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses = map[int]string{400: "custom detection body"}
	})
	wantSecurityHeaders := engine.ResponseHeaders()
	r := httptest.NewRequest("GET", "/search?q=<script>alert(1)</script>", nil)
	rec, p := serve(t, guard, r)
	if rec.Code != 400 || rec.Body.String() != "custom detection body" {
		t.Fatalf("custom error body must be reachable, got %d %q", rec.Code, rec.Body.String())
	}
	if p.called {
		t.Fatal("a blocked request must not reach the handler")
	}
	for name, value := range wantSecurityHeaders {
		if got := rec.Header().Get(name); got != value {
			t.Fatalf("blocked response must still carry security header %s = %q, got %q", name, value, got)
		}
	}
}
