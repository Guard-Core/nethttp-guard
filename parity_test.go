package nethttp

// Parity tests against the reference adapter (fastapi-guard): the response
// pass runs the custom response modifier last, and the request metrics and
// return rules see the real response status.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func serveWith(t *testing.T, engine *guardcore.Engine, handler http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	wrap, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	rec := httptest.NewRecorder()
	wrap(handler).ServeHTTP(rec, r)
	return rec
}

func TestParityModifierRewritesPassThroughResponse(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			resp.SetHeader("X-Modified", "yes")
			delete(resp.Headers, "X-Frame-Options")
			resp.Headers["X-Content-Type-Options"] = "changed"
			resp.Body = append([]byte("modified:"), resp.Body...)
			return resp
		}
	})
	rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	}, httptest.NewRequest("GET", "/api", nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("modifier must keep the handler status, got %d", rec.Code)
	}
	if rec.Body.String() != "modified:hello" {
		t.Fatalf("modifier must rewrite the pass-through body, got %q", rec.Body.String())
	}
	if rec.Header().Get("X-Modified") != "yes" {
		t.Fatalf("modifier header missing: %v", rec.Header())
	}
	if rec.Header().Get("X-Frame-Options") != "" {
		t.Fatalf("modifier must be able to drop a security header: %v", rec.Header())
	}
	if rec.Header().Get("X-Content-Type-Options") != "changed" {
		t.Fatalf("modifier must be able to change a header: %v", rec.Header())
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 2 {
		t.Fatalf("untouched multi-value headers must survive, got %v", got)
	}
	if rec.Header().Get("Content-Length") != "14" {
		t.Fatalf("content length must follow the modified body, got %q", rec.Header().Get("Content-Length"))
	}
}

func TestParityModifierRunsAfterCORSAndCORSIsReapplied(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.EnableCORS = true
		c.CORSAllowOrigins = []string{"https://app.example"}
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			sawCORS := resp.Headers["Access-Control-Allow-Origin"] == "https://app.example"
			delete(resp.Headers, "Access-Control-Allow-Origin")
			if sawCORS {
				resp.SetHeader("X-Saw-CORS", "yes")
			}
			return resp
		}
	})
	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Origin", "https://app.example")
	rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }, r)
	if rec.Header().Get("X-Saw-CORS") != "yes" {
		t.Fatalf("the modifier must see the CORS headers: %v", rec.Header())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("CORS is injected after the modifier in the reference dispatch: %v", rec.Header())
	}
}

func TestParityModifierAppliesToGuardBlockedResponse(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			resp.SetHeader("X-Modified", "yes")
			return resp
		}
	})
	rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) },
		httptest.NewRequest("GET", "/api?"+xssVector, nil))
	if rec.Code != 400 || rec.Header().Get("X-Modified") != "yes" {
		t.Fatalf("guard responses carry the modifier, got %d %v", rec.Code, rec.Header())
	}
}

func TestParityModifierStatusAndBodyFeedReturnRules(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response { return resp }
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "secret", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	for i := 0; i < 2; i++ {
		rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("a secret leaked here"))
		}, httptest.NewRequest("GET", "/report", nil))
		if rec.Code != 200 || rec.Body.String() != "a secret leaked here" {
			t.Fatalf("held response must reach the client intact, got %d %q", rec.Code, rec.Body.String())
		}
	}
	if !engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("the body prefix of a held response must reach the return rules")
	}
}

func TestParityHeldBodyBeyondBudgetIsNotScanned(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.BehaviorScanResponseBody = true
		c.BehaviorMaxResponseBodyInspectBytes = 1024
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response { return resp }
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "beyond-the-budget", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	big := []byte(strings.Repeat("a", 2048))
	copy(big[1500:], "beyond-the-budget")
	for i := 0; i < 3; i++ {
		rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(big) },
			httptest.NewRequest("GET", "/report", nil))
		if rec.Code != 200 || rec.Body.Len() != 2048 {
			t.Fatalf("the client must get the whole body, got %d with %d bytes", rec.Code, rec.Body.Len())
		}
	}
	if engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("a marker beyond the inspect budget must never trip a return rule")
	}
}

func TestParityHeldImplicitStatusAndNoBody(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
			resp.SetHeader("X-Status-Seen", http.StatusText(resp.StatusCode))
			return resp
		}
	})
	rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) {}, httptest.NewRequest("GET", "/empty", nil))
	if rec.Code != 200 || rec.Header().Get("X-Status-Seen") != "OK" {
		t.Fatalf("an empty handler answers the implicit 200, got %d %v", rec.Code, rec.Header())
	}
}

func TestParityStatusWithoutBodyWrite(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) {
		c.GlobalBehaviorRules = []guardcore.BehaviorRuleConfig{
			{RuleType: "return_pattern", Pattern: "status:500", Threshold: 1, Window: 60, Action: "ban"},
		}
	})
	for i := 0; i < 2; i++ {
		rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
			httptest.NewRequest("GET", "/boom", nil))
		if rec.Code != 500 {
			t.Fatalf("handler status must reach the client, got %d", rec.Code)
		}
	}
	if !engine.Ban.IsIPBanned("192.0.2.1") {
		t.Fatal("a 500 without a body must be reported to the engine as 500")
	}
}

// The engine's built-in default header exclusions (DefaultExcludedHeaders)
// keep address headers out of ssrf detection, so the examples and docs need
// no manual ExcludedDetectionHeaders workaround.
func TestParityAddressHeadersNeedNoManualExclusion(t *testing.T) {
	engine := newTestEngine(t, func(c *guardcore.SecurityConfig) { c.EnablePenetrationDetection = true })
	r := httptest.NewRequest("GET", "/api", nil)
	r.Host = "169.254.169.254"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("Origin", "http://localhost")
	rec := serveWith(t, engine, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }, r)
	if rec.Code != 200 {
		t.Fatalf("address headers must not be flagged by default, got %d %q", rec.Code, rec.Body.String())
	}
}
