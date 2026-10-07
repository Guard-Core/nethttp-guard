package nethttp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func wsTestEngine(t *testing.T, mutate func(*guardcore.SecurityConfig)) *guardcore.Engine {
	t.Helper()
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		c.EnableRedis = false
		if mutate != nil {
			mutate(c)
		}
	})
	if err != nil {
		t.Fatalf("NewSecurityConfig: %v", err)
	}
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

func wsUpgradeRequest(t *testing.T, remote string, mutate func(r *http.Request)) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.RemoteAddr = remote
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	if mutate != nil {
		mutate(r)
	}
	return r
}

func TestGuardWebSocketAllowsCleanUpgrade(t *testing.T) {
	engine := wsTestEngine(t, nil)
	if reason := GuardWebSocket(engine, wsUpgradeRequest(t, "203.0.113.9:12345", nil)); reason != nil {
		t.Fatalf("clean upgrade must pass, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(nil); status != http.StatusOK {
		t.Fatalf("nil reason must map to 200, got %d", status)
	}
}

func TestGuardWebSocketBannedIPCloses(t *testing.T) {
	engine := wsTestEngine(t, nil)
	if _, err := engine.Ban.Ban("203.0.113.9", 60, "test"); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	reason := GuardWebSocket(engine, wsUpgradeRequest(t, "203.0.113.9:12345", nil))
	if reason == nil || *reason != guardcore.WSCloseIPBanned {
		t.Fatalf("banned IP must close with the banned reason, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(reason); status != http.StatusForbidden {
		t.Fatalf("policy violation must map to 403, got %d", status)
	}
}

func TestGuardWebSocketBlacklistedIPCloses(t *testing.T) {
	engine := wsTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.Blacklist = []string{"203.0.113.9"}
	})
	reason := GuardWebSocket(engine, wsUpgradeRequest(t, "203.0.113.9:12345", nil))
	if reason == nil || *reason != guardcore.WSCloseIPNotAllowed {
		t.Fatalf("blacklisted IP must close with the not-allowed reason, got %+v", reason)
	}
}

func TestGuardWebSocketSuspiciousHandshakeCloses(t *testing.T) {
	engine := wsTestEngine(t, nil)
	r := wsUpgradeRequest(t, "203.0.113.9:12345", func(r *http.Request) {
		r.URL.Path = "/ws/search"
		r.URL.RawQuery = "q=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
	})
	reason := GuardWebSocket(engine, r)
	if reason == nil || *reason != guardcore.WSCloseSuspiciousActivity {
		t.Fatalf("suspicious handshake must close with the suspicious reason, got %+v", reason)
	}
}

func TestGuardWebSocketFailSecureUnknownAddress(t *testing.T) {
	engine := wsTestEngine(t, nil) // fail_secure defaults true
	r := wsUpgradeRequest(t, "", nil)
	r.RemoteAddr = ""
	reason := GuardWebSocket(engine, r)
	if reason == nil || *reason != guardcore.WSCloseClientAddressUnknown {
		t.Fatalf("unknown address under fail_secure must close, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(reason); status != http.StatusForbidden {
		t.Fatalf("client-address-unknown must map to 403, got %d", status)
	}
}

func TestGuardWebSocketNilEngineFailsClosed(t *testing.T) {
	reason := GuardWebSocket(nil, wsUpgradeRequest(t, "203.0.113.9:12345", nil))
	if reason == nil || *reason != guardcore.WSCloseSecurityCheckFailed {
		t.Fatalf("nil engine must fail closed, got %+v", reason)
	}
	if status := WebSocketHTTPStatus(reason); status != http.StatusServiceUnavailable {
		t.Fatalf("security-check-failed must map to 503, got %d", status)
	}
}

func TestWSRequestShimContract(t *testing.T) {
	r := wsUpgradeRequest(t, "203.0.113.9:12345", func(r *http.Request) {
		r.Header["X-Custom"] = []string{"one", "two"}
		r.URL.RawQuery = "a=1&a=2"
	})
	r.URL.Scheme = "https"
	r.TLS = &tls.ConnectionState{}
	shim := newWSRequestShim(r)
	if shim.Method() != "WEBSOCKET" {
		t.Fatalf("the ws shim must report the WEBSOCKET method, got %q", shim.Method())
	}
	if body, err := shim.Body(); err != nil || body != nil {
		t.Fatalf("the ws shim must carry an empty body, got (%v, %v)", body, err)
	}
	if joined, _ := shim.Headers().Get("X-Custom"); joined != "one, two" {
		t.Fatalf("repeated headers must join with a comma, got %q", joined)
	}
	if shim.QueryParams()["a"] != "1" {
		t.Fatalf("query params must keep the first value, got %q", shim.QueryParams()["a"])
	}
	if shim.ClientHost() != "203.0.113.9" {
		t.Fatalf("client host must strip the port, got %q", shim.ClientHost())
	}
	if shim.State() == nil {
		t.Fatal("the ws shim must expose a request state")
	}
	if shim.URLScheme() != "https" {
		t.Fatalf("the ws shim must resolve the request scheme, got %q", shim.URLScheme())
	}
	if full := shim.URLFull(); full != "https://example.com/ws?a=1&a=2" {
		t.Fatalf("the ws shim must build the full URL, got %q", full)
	}
	if replaced := shim.URLReplaceScheme("wss"); replaced != "wss://example.com/ws?a=1&a=2" {
		t.Fatalf("scheme replacement must swap the scheme, got %q", replaced)
	}
	if same := shim.URLReplaceScheme(""); same != shim.URLFull() {
		t.Fatalf("empty scheme replacement must keep the URL, got %q", same)
	}

	plain := newWSRequestShim(wsUpgradeRequest(t, "203.0.113.9:12345", nil))
	if plain.URLScheme() != "http" {
		t.Fatalf("a plaintext request must resolve http, got %q", plain.URLScheme())
	}
	if full := plain.URLFull(); full != "http://example.com/ws" {
		t.Fatalf("the ws shim must build the plain full URL, got %q", full)
	}
}
