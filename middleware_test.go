package nethttp

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const xssVector = "q=<script>alert(1)</script>"

type probe struct {
	called   bool
	headers  http.Header
	body     []byte
	method   string
	path     string
	rawQuery string
}

func newTestEngine(t *testing.T, mutate func(*guardcore.SecurityConfig)) *guardcore.Engine {
	t.Helper()
	cfg := guardcore.DefaultSecurityConfig()
	cfg.EnableRedis = false
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return engine
}

func newTestMiddleware(t *testing.T, mutate func(*guardcore.SecurityConfig), opts ...Option) (func(http.Handler) http.Handler, *guardcore.Engine) {
	t.Helper()
	engine := newTestEngine(t, mutate)
	wrap, err := New(engine, opts...)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	return wrap, engine
}

func serve(t *testing.T, wrap func(http.Handler) http.Handler, r *http.Request) (*httptest.ResponseRecorder, *probe) {
	t.Helper()
	p := &probe{}
	next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p.called = true
		p.headers = w.Header().Clone()
		p.body, _ = io.ReadAll(req.Body)
		p.method = req.Method
		p.path = req.URL.Path
		p.rawQuery = req.URL.RawQuery
	})
	rec := httptest.NewRecorder()
	wrap(next).ServeHTTP(rec, r)
	return rec, p
}

func TestMiddlewareNilEngineRejected(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil engine must be rejected")
	}
}

func TestMiddlewareAllowsRequestUnmutated(t *testing.T) {
	wrap, _ := newTestMiddleware(t, nil)
	r := httptest.NewRequest("GET", "/api/users?v=1", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("clean request must reach the handler, got %d called=%v", rec.Code, p.called)
	}
	if p.method != "GET" || p.path != "/api/users" || p.rawQuery != "v=1" {
		t.Fatalf("handler must see the original request, got %s %s?%s", p.method, p.path, p.rawQuery)
	}
}

// Security headers land on every pass-through response, applied by the
// adapter from the engine's ResponseHeaders() set.
func TestMiddlewareAppliesSecurityHeadersOnPass(t *testing.T) {
	wrap, engine := newTestMiddleware(t, nil)
	want := engine.ResponseHeaders()
	if len(want) == 0 {
		t.Fatal("default config must produce security headers")
	}
	r := httptest.NewRequest("GET", "/api/users", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("clean request must pass, got %d called=%v", rec.Code, p.called)
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Fatalf("security header %s = %q, want %q", name, got, value)
		}
	}
	if len(p.headers) != len(want) {
		t.Fatalf("handler must see exactly the security headers, got %d want %d", len(p.headers), len(want))
	}

	// Disabled security headers restore the header-free pass.
	disabled, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.SecurityHeaders.Enabled = false
	})
	rec, p = serve(t, disabled, httptest.NewRequest("GET", "/api/users", nil))
	if rec.Code != 200 || !p.called {
		t.Fatalf("disabled-headers request must pass, got %d called=%v", rec.Code, p.called)
	}
	if len(p.headers) != 0 {
		t.Fatalf("disabled security headers must add nothing on pass, got %v", p.headers)
	}
}

// Config overrides and custom headers flow through the adapter untouched.
func TestMiddlewareSecurityHeadersHonorsConfig(t *testing.T) {
	wrap, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.SecurityHeaders.FrameOptions = "DENY"
		c.SecurityHeaders.Custom = map[string]string{"X-Request-Realm": "edge"}
	})
	want := engine.ResponseHeaders()
	r := httptest.NewRequest("GET", "/api", nil)
	rec, _ := serve(t, wrap, r)
	if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("X-Request-Realm") != "edge" {
		t.Fatalf("overrides and custom headers must reach the response, got %v", rec.Header())
	}
	if len(rec.Header()) != len(want) {
		t.Fatalf("response must carry exactly the engine set, got %d want %d", len(rec.Header()), len(want))
	}
}

func TestMiddlewareBlocksBannedIPExactly(t *testing.T) {
	wrap, engine := newTestMiddleware(t, nil)
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, wrap, r)
	if rec.Code != 403 {
		t.Fatalf("banned IP must be 403, got %d", rec.Code)
	}
	if rec.Body.String() != guardcore.IPBanBlockedMessage {
		t.Fatalf("body must be the error factory body %q, got %q", guardcore.IPBanBlockedMessage, rec.Body.String())
	}
	if p.called {
		t.Fatal("blocked request must not reach the handler")
	}
	// The guard-core-go v4.1.0 floor makes blocked responses carry the
	// engine's default security headers, so the adapter must translate
	// exactly that set: every header present, verbatim, and nothing beyond
	// it (the adapter adds nothing and strips nothing).
	engineDefaultSecurityHeaders := map[string]string{
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "SAMEORIGIN",
		"X-XSS-Protection":                  "1; mode=block",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"Permissions-Policy":                "geolocation=(), microphone=(), camera=()",
		"X-Permitted-Cross-Domain-Policies": "none",
		"X-Download-Options":                "noopen",
		"Cross-Origin-Embedder-Policy":      "require-corp",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
	}
	for name, want := range engineDefaultSecurityHeaders {
		values, ok := rec.Header()[http.CanonicalHeaderKey(name)]
		if !ok {
			t.Fatalf("blocked response must carry the engine default security header %s, got %v", name, rec.Header())
		}
		if len(values) != 1 || values[0] != want {
			t.Fatalf("blocked response security header %s = %v, want [%q] verbatim", name, values, want)
		}
	}
	if len(rec.Header()) != len(engineDefaultSecurityHeaders) {
		t.Fatalf("verdict headers must translate exactly, nothing beyond the engine default security headers, got %v", rec.Header())
	}
}

func TestMiddlewareCustomErrorMessage(t *testing.T) {
	wrap, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses[403] = "denied by policy"
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	rec, _ := serve(t, wrap, r)
	if rec.Code != 403 || rec.Body.String() != "denied by policy" {
		t.Fatalf("custom message must be translated verbatim, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareTranslatesRedirectVerdictHeaders(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnforceHTTPS = true
	})
	r := httptest.NewRequest("GET", "http://example.com/api", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 301 || p.called {
		t.Fatalf("http request must redirect with 301, got %d called=%v", rec.Code, p.called)
	}
	if location := rec.Header().Get("Location"); location != "https://example.com/api" {
		t.Fatalf("Location header must come from the verdict, got %q", location)
	}
}

func TestMiddlewarePOSTBodyScannedAndReplayed(t *testing.T) {
	var firstRead, secondRead []byte
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			firstRead, _ = req.Body()
			secondRead, _ = req.Body()
			if bytes.Contains(firstRead, []byte("evil")) {
				return &guardcore.Response{StatusCode: 403, Body: []byte("malicious body")}
			}
			return nil
		}
	})
	benign := httptest.NewRequest("POST", "/submit", strings.NewReader("hello world"))
	rec, p := serve(t, wrap, benign)
	if rec.Code != 200 || !p.called || string(p.body) != "hello world" {
		t.Fatalf("benign body must pass and be replayed to the handler, got %d body=%q handler-body=%q", rec.Code, "hello world", p.body)
	}
	if !bytes.Equal(firstRead, secondRead) {
		t.Fatalf("Body() must be idempotent, got %q then %q", firstRead, secondRead)
	}
	evilm := httptest.NewRequest("POST", "/submit", strings.NewReader("evil payload"))
	rec, p = serve(t, wrap, evilm)
	if rec.Code != 403 || rec.Body.String() != "malicious body" || p.called {
		t.Fatalf("body content must block, got %d %q called=%v", rec.Code, rec.Body.String(), p.called)
	}
}

func TestMiddlewareBoundedBodyOnlyScansPrefix(t *testing.T) {
	var seenLen int
	var seen []byte
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			seen, _ = req.Body()
			seenLen = len(seen)
			if bytes.Contains(seen, []byte("evil")) {
				return &guardcore.Response{StatusCode: 403, Body: []byte("malicious body")}
			}
			return nil
		}
	}, WithMaxBodyBytes(16))
	payload := strings.Repeat("x", 20) + "evil" + strings.Repeat("y", 40)
	oversize := httptest.NewRequest("POST", "/submit", strings.NewReader(payload))
	rec, p := serve(t, wrap, oversize)
	if rec.Code != 200 || !p.called {
		t.Fatalf("marker beyond the bounded prefix must pass, got %d called=%v", rec.Code, p.called)
	}
	if seenLen != 16 {
		t.Fatalf("engine must only see the bounded prefix, got %d bytes", seenLen)
	}
	if string(p.body) != payload {
		t.Fatal("handler must still receive the full body")
	}
	inline := httptest.NewRequest("POST", "/submit", strings.NewReader("evil"+strings.Repeat("x", 60)))
	rec, p = serve(t, wrap, inline)
	if rec.Code != 403 || p.called {
		t.Fatalf("marker inside the prefix must block, got %d called=%v", rec.Code, p.called)
	}
}

func TestRequestShimBoundedPrefixAndReplay(t *testing.T) {
	body := strings.Repeat("A", 12) + "TAIL"
	r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	shim := newRequestShim(r, 8)
	prefix, err := shim.ReadBodyPrefix(4)
	if err != nil || string(prefix) != "AAAA" {
		t.Fatalf("prefix read must return 4 bytes, got %q err=%v", prefix, err)
	}
	if extended, _ := shim.ReadBodyPrefix(8); string(extended) != strings.Repeat("A", 8) {
		t.Fatalf("prefix must extend contiguously, got %q", extended)
	}
	cached, err := shim.Body()
	if err != nil || len(cached) != 8 {
		t.Fatalf("Body() must be bounded by MaxBodyBytes, got %d bytes err=%v", len(cached), err)
	}
	replayed, err := io.ReadAll(r.Body)
	if err != nil || string(replayed) != body {
		t.Fatalf("replay must restore the full body, got %d bytes err=%v", len(replayed), err)
	}
}

func TestRequestShimWithoutEngineReadStreamsUntouched(t *testing.T) {
	body := "stream-me"
	r := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	newRequestShim(r, 64)
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != body {
		t.Fatalf("un-read body must stream through untouched, got %q err=%v", got, err)
	}
}

func TestMiddlewareRouteBypassAll(t *testing.T) {
	wrap, engine := newTestMiddleware(t, nil)
	engine.Routes.Register("open", func(rc *guardcore.RouteConfig) {
		rc.BypassedChecks = []string{"all"}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	r.RemoteAddr = "203.0.113.7:4711"
	r = r.WithContext(WithRouteID(r.Context(), "open"))
	rec, p := serve(t, wrap, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("bypass-all route must reach the handler even for banned IPs, got %d called=%v", rec.Code, p.called)
	}
	plain := httptest.NewRequest("GET", "/api", nil)
	plain.RemoteAddr = "203.0.113.7:4711"
	rec, p = serve(t, wrap, plain)
	if rec.Code != 403 || p.called {
		t.Fatalf("without the route id the ban must hold, got %d called=%v", rec.Code, p.called)
	}
}

func TestMiddlewareExclusionScoping(t *testing.T) {
	wrap, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.ExcludePaths = []string{"/public"}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	banned := httptest.NewRequest("GET", "/public/data", nil)
	banned.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, wrap, banned)
	if rec.Code != 403 || p.called {
		t.Fatalf("ip ban stays enforced on excluded paths, got %d called=%v", rec.Code, p.called)
	}
	excluded := httptest.NewRequest("GET", "/public?"+xssVector, nil)
	rec, p = serve(t, wrap, excluded)
	if rec.Code != 200 || !p.called {
		t.Fatalf("suspicious detection must be skipped in exclusion scope, got %d called=%v", rec.Code, p.called)
	}
	scoped := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	rec, p = serve(t, wrap, scoped)
	if rec.Code != 400 || p.called {
		t.Fatalf("same vector outside exclusions must be blocked, got %d called=%v", rec.Code, p.called)
	}
}

func TestMiddlewarePassiveModePassesThrough(t *testing.T) {
	var hookPayloads []map[string]any
	wrap, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.PassiveMode = true
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			hookPayloads = append(hookPayloads, payload)
		}
	})
	if _, err := engine.Ban.Ban("203.0.113.7", 60, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	banned := httptest.NewRequest("GET", "/api", nil)
	banned.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, wrap, banned)
	if rec.Code != 200 || !p.called {
		t.Fatalf("passive mode must pass through even for banned IPs, got %d called=%v", rec.Code, p.called)
	}
	vector := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	rec, p = serve(t, wrap, vector)
	if rec.Code != 200 || !p.called {
		t.Fatalf("passive mode must pass through detection, got %d called=%v", rec.Code, p.called)
	}
	if len(hookPayloads) != 2 {
		t.Fatalf("passive mode must fire the on_block hook per corpus: ip_security for the banned pass-through, then suspicious_activity for detection, got %v", hookPayloads)
	}
	if hookPayloads[0]["check_name"] != "ip_security" || hookPayloads[0]["passive_mode"] != true {
		t.Fatalf("banned-IP pass-through must fire the ip_security hook with passive_mode true, got %v", hookPayloads[0])
	}
	if hookPayloads[1]["check_name"] != "suspicious_activity" || hookPayloads[1]["passive_mode"] != true {
		t.Fatalf("detection pass-through must fire the suspicious_activity hook with passive_mode true, got %v", hookPayloads[1])
	}
}

func TestMiddlewareWhitelistHonored(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.Whitelist = []string{"203.0.113.7"}
	})
	allowed := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	allowed.RemoteAddr = "203.0.113.7:4711"
	rec, p := serve(t, wrap, allowed)
	if rec.Code != 200 || !p.called {
		t.Fatalf("whitelisted IP must pass, got %d called=%v", rec.Code, p.called)
	}
	other := httptest.NewRequest("GET", "/search?"+xssVector, nil)
	rec, p = serve(t, wrap, other)
	if rec.Code != 403 || p.called {
		t.Fatalf("non-whitelisted IP must be denied by ip security, got %d called=%v", rec.Code, p.called)
	}
}

func TestMiddlewareCustomCheckPanicFailsClosed(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("validator exploded")
		}
	})
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 500 || p.called {
		t.Fatalf("fail-secure must translate to 500 without reaching the handler, got %d called=%v", rec.Code, p.called)
	}
	if rec.Body.String() != "Security check failed" {
		t.Fatalf("fail-secure body mismatch, got %q", rec.Body.String())
	}
}

func TestMiddlewareFailClosedHonorsCustomMessage(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomErrorResponses[500] = "upstream refused"
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("validator exploded")
		}
	})
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 500 || rec.Body.String() != "upstream refused" || p.called {
		t.Fatalf("fail-closed must honor the custom 500 message, got %d %q called=%v", rec.Code, rec.Body.String(), p.called)
	}
}

func TestMiddlewareWithLoggerReceivesFailClosed(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	m := &middleware{engine: &guardcore.Engine{}, maxBytes: DefaultMaxBodyBytes, logger: logger}
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, m.wrap, r)
	if rec.Code != 500 || p.called {
		t.Fatalf("malfunctioning engine must fail closed, got %d called=%v", rec.Code, p.called)
	}
	if rec.Body.String() != failClosedMessage {
		t.Fatalf("fail-closed body mismatch, got %q", rec.Body.String())
	}
	if !strings.Contains(buf.String(), "engine malfunction, failing closed") || !strings.Contains(buf.String(), "engine panic:") {
		t.Fatalf("custom logger must receive the malfunction detail, got %q", buf.String())
	}
}

func TestMiddlewareInvalidOptionsIgnored(t *testing.T) {
	engine := newTestEngine(t, nil)
	wrap, err := New(engine, WithMaxBodyBytes(-1), WithLogger(nil))
	if err != nil {
		t.Fatalf("invalid option values must be ignored, got %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 200 || !p.called {
		t.Fatalf("middleware with defaults must pass clean traffic, got %d called=%v", rec.Code, p.called)
	}
}
