package nethttp

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// wsUpgradeRequest builds a WebSocket upgrade request the way a browser
// sends it.
func wsUpgradeRequest(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	return r
}

// TestIsWebSocketUpgrade pins the upgrade detection.
func TestIsWebSocketUpgrade(t *testing.T) {
	if !IsWebSocketUpgrade(wsUpgradeRequest("/ws")) {
		t.Fatal("a websocket upgrade must detect")
	}
	half := httptest.NewRequest(http.MethodGet, "/ws", nil)
	half.Header.Set("Upgrade", "websocket")
	if IsWebSocketUpgrade(half) {
		t.Fatal("an upgrade without the Connection token is not an upgrade")
	}
	plain := httptest.NewRequest(http.MethodGet, "/ws", nil)
	plain.Header.Set("Upgrade", "h2c")
	if IsWebSocketUpgrade(plain) {
		t.Fatal("a non-websocket upgrade must not detect")
	}
}

// TestWebSocketGuardAllowedUpgrade: a clean upgrade reaches the handler
// with the upgrade headers intact.
func TestWebSocketGuardAllowedUpgrade(t *testing.T) {
	wrap, _ := newTestMiddleware(t, nil)
	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		if r.Header.Get("Upgrade") != "websocket" {
			t.Errorf("the handler must see the upgrade headers, got %q", r.Header.Get("Upgrade"))
		}
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	wrap(handler).ServeHTTP(rec, wsUpgradeRequest("/ws"))
	if !handlerCalled {
		t.Fatal("a clean upgrade must reach the handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("the handler's status must pass through, got %d", rec.Code)
	}
}

// TestWebSocketGuardRejectedSuspicious: an upgrade whose handshake
// carries an attack payload answers the reference's suspicious-activity
// close shape instead of a plain error.
func TestWebSocketGuardRejectedSuspicious(t *testing.T) {
	wrap, _ := newTestMiddleware(t, nil)
	req := wsUpgradeRequest("/ws?q=" + xssVector)
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a blocked upgrade must not reach the handler")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the handshake must reject with 403, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseCodeHeader); got != "1008" {
		t.Fatalf("close code drifted: %q", got)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != WSCloseSuspiciousActivity.Reason {
		t.Fatalf("close reason drifted: %q", got)
	}
	if !strings.Contains(rec.Body.String(), WSCloseSuspiciousActivity.Reason) {
		t.Fatalf("the body must carry the reason, got %q", rec.Body.String())
	}
}

// TestWebSocketGuardRejectedRateLimit: the rate-limited upgrade maps to
// the rate-limit close shape.
func TestWebSocketGuardRejectedRateLimit(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnableRateLimiting = true
		c.RateLimit = 1
		c.RateLimitWindow = 60
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// First upgrade consumes the quota.
	first := httptest.NewRecorder()
	wrap(handler).ServeHTTP(first, wsUpgradeRequest("/ws"))
	if first.Code != http.StatusOK {
		t.Fatalf("the first upgrade must pass, got %d", first.Code)
	}
	second := httptest.NewRecorder()
	wrap(handler).ServeHTTP(second, wsUpgradeRequest("/ws"))
	if second.Code != http.StatusForbidden {
		t.Fatalf("the second upgrade must reject, got %d", second.Code)
	}
	if got := second.Header().Get(WebSocketCloseCodeHeader); got != "1008" {
		t.Fatalf("close code drifted: %q", got)
	}
	if got := second.Header().Get(WebSocketCloseReasonHeader); got != WSCloseRateLimitExceeded.Reason {
		t.Fatalf("close reason drifted: %q", got)
	}
}

// TestWebSocketGuardRejectedBanned: a banned identity maps to the
// IP-banned close shape.
func TestWebSocketGuardRejectedBanned(t *testing.T) {
	wrap, engine := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.EnableIPBanning = true
	})
	if _, err := engine.Ban.Ban("192.0.2.7", 300, "test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	req := wsUpgradeRequest("/ws")
	req.RemoteAddr = "192.0.2.7:51000"
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a banned identity must not reach the handler")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the handshake must reject, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != WSCloseIPBanned.Reason {
		t.Fatalf("close reason drifted: %q (body %q)", got, rec.Body.String())
	}
}

// TestWebSocketGuardRejectedBlacklist: a blacklisted identity maps to
// the IP-not-allowed close shape.
func TestWebSocketGuardRejectedBlacklist(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.Blacklist = []string{"192.0.2.9"}
	})
	req := wsUpgradeRequest("/ws")
	req.RemoteAddr = "192.0.2.9:51000"
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a blacklisted identity must not reach the handler")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the handshake must reject, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != WSCloseIPNotAllowed.Reason {
		t.Fatalf("close reason drifted: %q (body %q)", got, rec.Body.String())
	}
}

// TestWebSocketGuardPassiveMode: passive mode lets the blocked upgrade
// through (the engine answers no verdict).
func TestWebSocketGuardPassiveMode(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.BlockedUserAgents = []string{"^evilclient"}
		c.PassiveMode = true
	})
	req := wsUpgradeRequest("/ws")
	req.Header.Set("User-Agent", "evilclient/1.0")
	called := false
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	if !called {
		t.Fatal("passive mode must let the upgrade through")
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != "" {
		t.Fatalf("passive mode must not carry close shapes, got %q", got)
	}
}

// TestWebSocketGuardUnknownAddressFailSecure: an upgrade without a
// determinable client address fails closed under the default
// fail-secure config, and passes when fail_secure is off.
func TestWebSocketGuardUnknownAddressFailSecure(t *testing.T) {
	wrap, _ := newTestMiddleware(t, nil)
	req := wsUpgradeRequest("/ws")
	req.RemoteAddr = ""
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("an unknown address must fail closed by default")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the handshake must reject, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != WSCloseClientAddressUnknown.Reason {
		t.Fatalf("close reason drifted: %q", got)
	}

	wrap2, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.FailSecure = false
	})
	rec2 := httptest.NewRecorder()
	called := false
	wrap2(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec2, req)
	if !called {
		t.Fatal("fail_secure=false must let the upgrade through")
	}
}

// TestWebSocketGuardDisabled: WithWebSocketGuard(false) restores the
// plain blocked-response shape (no close-shape headers).
func TestWebSocketGuardDisabled(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.BlockedUserAgents = []string{"^evilclient"}
	}, WithWebSocketGuard(false))
	req := wsUpgradeRequest("/ws")
	req.Header.Set("User-Agent", "evilclient/1.0")
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a blocked upgrade must not reach the handler")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the plain block shape must stay 403, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != "" {
		t.Fatalf("a disabled guard must not carry close shapes, got %q", got)
	}
}

// TestWebSocketGuardCheckFailureMapsToSecurityCheckFailed: an engine
// check failure (the pipeline's fail-secure 500) answers the
// security-check-failed close shape (1013).
func TestWebSocketGuardCheckFailureMapsToSecurityCheckFailed(t *testing.T) {
	wrap, _ := newTestMiddleware(t, func(c *guardcore.SecurityConfig) {
		c.CustomRequestCheck = func(req guardcore.Request) *guardcore.Response {
			panic("boom")
		}
	})
	rec := httptest.NewRecorder()
	wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a failing check must not reach the handler")
	})).ServeHTTP(rec, wsUpgradeRequest("/ws"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the fail-closed handshake must reject, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != WSCloseSecurityCheckFailed.Reason {
		t.Fatalf("close reason drifted: %q", got)
	}
	if got := rec.Header().Get(WebSocketCloseCodeHeader); got != "1013" {
		t.Fatalf("close code drifted: %q", got)
	}
}

// TestWebSocketGuardEngineMalfunctionFailsClosed: a malfunctioning
// engine (Check errors) on an upgrade answers the same 1013 close shape
// through the adapter's fail-closed branch.
func TestWebSocketGuardEngineMalfunctionFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	engine := &guardcore.Engine{Config: guardcore.DefaultSecurityConfig()}
	m := &middleware{engine: engine, maxBytes: DefaultMaxBodyBytes, logger: log.New(&buf, "", 0), wsGuard: true}
	rec := httptest.NewRecorder()
	m.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a malfunctioning engine must not reach the handler")
	})).ServeHTTP(rec, wsUpgradeRequest("/ws"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the fail-closed handshake must reject, got %d", rec.Code)
	}
	if got := rec.Header().Get(WebSocketCloseReasonHeader); got != WSCloseSecurityCheckFailed.Reason {
		t.Fatalf("close reason drifted: %q", got)
	}
	if got := rec.Header().Get(WebSocketCloseCodeHeader); got != "1013" {
		t.Fatalf("close code drifted: %q", got)
	}
	if !strings.Contains(buf.String(), "engine malfunction, failing closed") {
		t.Fatalf("the malfunction must be reported, got %q", buf.String())
	}
}

// TestRequestShimJoinsMultiLineXFF pins the reference's
// _join_repeated_header_lines behavior the chain walk depends on: an
// X-Forwarded-For chain split across repeated header lines reaches the
// engine as one chain.
func TestRequestShimJoinsMultiLineXFF(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Add("X-Forwarded-For", "203.0.113.5")
	r.Header.Add("X-Forwarded-For", "198.51.100.9")
	shim := newRequestShim(r, DefaultMaxBodyBytes)
	got, ok := shim.Headers().Get("X-Forwarded-For")
	if !ok || got != "203.0.113.5, 198.51.100.9" {
		t.Fatalf("multi-line XFF must join into one chain, got %q ok=%v", got, ok)
	}

	// End to end: the trusted-proxy chain walk resolves the client from
	// the joined lines.
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.TrustedProxies = []string{"10.0.0.1"}
	})
	req := guardcore.NewRequestFactory().CreateRequest(guardcore.RequestOptions{
		Path:       "/api",
		Method:     "GET",
		ClientHost: "10.0.0.1",
		Header: map[string]string{
			"X-Forwarded-For": "203.0.113.5, 198.51.100.9",
		},
	})
	if err := engine.Check(req); err == nil {
		// Check returns a response for blocks only; a pass is nil.
		_ = err
	}
	if got := req.State().ClientIP; got != "198.51.100.9" {
		t.Fatalf("the joined chain must resolve depth-1, got %q", got)
	}
}
