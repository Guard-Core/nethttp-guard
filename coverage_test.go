package nethttp

// Coverage tests: pin the remaining branch behavior of the adapter
// surface, option plumbing, request-shim edge conversions, bounded body
// cache fills, replay body edges, and the body-capture budget gate.

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// WithLogger must install the provided logger: the fail-closed path then
// reports the engine malfunction through it instead of the default logger.
func TestWithLoggerInstallsProvidedLogger(t *testing.T) {
	var buf bytes.Buffer
	wrap, err := New(&guardcore.Engine{}, WithLogger(log.New(&buf, "", 0)))
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	r := httptest.NewRequest("GET", "/api", nil)
	rec, p := serve(t, wrap, r)
	if rec.Code != 500 || p.called {
		t.Fatalf("malfunctioning engine must fail closed, got %d called=%v", rec.Code, p.called)
	}
	if !strings.Contains(buf.String(), "engine malfunction, failing closed") {
		t.Fatalf("the provided logger must receive the malfunction report, got %q", buf.String())
	}
}

// A scan flag on with a non-positive inspect budget must still disable the
// body capture: there is no budget to inspect with.
func TestBodyCaptureDisabledWithoutBudget(t *testing.T) {
	m := &middleware{engine: &guardcore.Engine{Config: &guardcore.SecurityConfig{BehaviorScanResponseBody: true}}}
	if m.newBodyCapture() != nil {
		t.Fatal("non-positive inspect budget must disable the body capture")
	}
}

// Request-shim conversions on the edges: nil body, TLS requests, empty
// method, portless RemoteAddr, and the default body budget.
func TestRequestShimEdgeConversions(t *testing.T) {
	r := httptest.NewRequest("GET", "/api", nil)
	r.Body = nil
	r.TLS = &tls.ConnectionState{}
	r.Method = ""
	shim := newRequestShim(r, DefaultMaxBodyBytes)
	if shim.URLScheme() != "https" {
		t.Fatalf("TLS request must resolve scheme https, got %q", shim.URLScheme())
	}
	if shim.Method() != "GET" {
		t.Fatalf("empty method must default to GET, got %q", shim.Method())
	}
	if full := shim.URLFull(); full != "https://example.com/api" {
		t.Fatalf("URL without a query must have no question mark, got %q", full)
	}
	queried := newRequestShim(httptest.NewRequest("GET", "https://example.com/api?tag=first&page=2", nil), DefaultMaxBodyBytes)
	if full := queried.URLFull(); full != "https://example.com/api?tag=first&page=2" {
		t.Fatalf("URL with a query must carry it verbatim, got %q", full)
	}
	if replaced := shim.URLReplaceScheme(""); replaced != "https://example.com/api" {
		t.Fatalf("empty scheme replacement must return the full URL untouched, got %q", replaced)
	}
	portless := newRequestShim(func() *http.Request {
		pr := httptest.NewRequest("GET", "/api", nil)
		pr.RemoteAddr = "203.0.113.9"
		return pr
	}(), DefaultMaxBodyBytes)
	if host := portless.ClientHost(); host != "203.0.113.9" {
		t.Fatalf("RemoteAddr without a port must pass through, got %q", host)
	}
	if _, err := shim.Body(); err != nil {
		t.Fatalf("nil body must read as empty without error, got %v", err)
	}
	nonPositive := newRequestShim(httptest.NewRequest("GET", "/api", nil), 0)
	if nonPositive.maxBytes != DefaultMaxBodyBytes {
		t.Fatalf("non-positive body budget must fall back to the default, got %d", nonPositive.maxBytes)
	}
}

// ReadBodyPrefix clamps negative bounds to zero, caps requests at the
// configured budget, and extends the cache contiguously on a follow-up
// read.
func TestReadBodyPrefixNegativeBound(t *testing.T) {
	r := httptest.NewRequest("POST", "/submit", strings.NewReader("hello"))
	shim := newRequestShim(r, 4)
	prefix, err := shim.ReadBodyPrefix(-4)
	if err != nil || len(prefix) != 0 {
		t.Fatalf("negative bound must read nothing, got %q err=%v", prefix, err)
	}
	if extended, _ := shim.ReadBodyPrefix(16); string(extended) != "hell" {
		t.Fatalf("over-budget read must cap at the configured budget, got %q", extended)
	}
	if again, _ := shim.ReadBodyPrefix(4); string(again) != "hell" {
		t.Fatalf("follow-up read must extend contiguously, got %q", again)
	}
}

// A read error other than EOF must surface from the prefix read, and a
// reader yielding (0, nil) must not spin the cache fill: the fill stops
// without error and a later replay still drains the same source.
func TestFillCacheStopsOnZeroRead(t *testing.T) {
	failing := &errReader{err: errors.New("read exploded")}
	r := httptest.NewRequest("POST", "/submit", failing)
	shim := newRequestShim(r, DefaultMaxBodyBytes)
	if _, err := shim.ReadBodyPrefix(8); err == nil || err.Error() != "read exploded" {
		t.Fatalf("non-EOF read error must surface, got %v", err)
	}
	source := &zeroOnceReader{}
	zero := newRequestShim(httptest.NewRequest("POST", "/submit", source), DefaultMaxBodyBytes)
	prefix, err := zero.ReadBodyPrefix(8)
	if err != nil || len(prefix) != 0 {
		t.Fatalf("zero-byte read must stop the fill without error, got %q err=%v", prefix, err)
	}
	if _, err := io.ReadAll(zero.req.Body); err != nil {
		t.Fatalf("replay must still drain the source, got %v", err)
	}
}

type zeroOnceReader struct{ calls int }

func (z *zeroOnceReader) Read(p []byte) (int, error) {
	z.calls++
	if z.calls == 1 {
		return 0, nil
	}
	return 0, io.EOF
}

type errReader struct{ err error }

func (e *errReader) Read(p []byte) (int, error) { return 0, e.err }

// Zero-length replay reads must be a no-op, and Close must forward to the
// original body (and tolerate having none).
func TestReplayBodyEdges(t *testing.T) {
	r := httptest.NewRequest("POST", "/submit", strings.NewReader("payload"))
	newRequestShim(r, DefaultMaxBodyBytes)
	if n, err := r.Body.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero-length read must be a no-op, got %d %v", n, err)
	}
	if err := r.Body.Close(); err != nil {
		t.Fatalf("close must forward to the original body, got %v", err)
	}
	empty := &replayBody{shim: &requestShim{}}
	if err := empty.Close(); err != nil {
		t.Fatalf("close without an original body must be a no-op, got %v", err)
	}
}
