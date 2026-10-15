package nethttp

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func modifierConfig(c *guardcore.SecurityConfig) {
	c.CustomResponseModifier = func(resp *guardcore.Response) *guardcore.Response {
		resp.SetHeader("X-Modified", "yes")
		return resp
	}
}

func startGuarded(t *testing.T, mutate func(*guardcore.SecurityConfig), h http.HandlerFunc) *httptest.Server {
	t.Helper()
	wrap, _ := newTestMiddleware(t, mutate)
	srv := httptest.NewServer(wrap(h))
	t.Cleanup(srv.Close)
	return srv
}

func TestObserverFlushStreamsThroughRealServer(t *testing.T) {
	release := make(chan struct{})
	srv := startGuarded(t, nil, func(w http.ResponseWriter, r *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("the wrapped writer must expose http.Flusher")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: one\n\n"))
		f.Flush()
		<-release
		_, _ = w.Write([]byte("data: two\n\n"))
	})
	resp, err := http.Get(srv.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first event must arrive before the handler finishes, got %q err %v", line, err)
	}
	close(release)
}

func TestObserverResponseControllerFlushAndUnwrap(t *testing.T) {
	release := make(chan struct{})
	srv := startGuarded(t, nil, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first\n"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
		<-release
	})
	resp, err := http.Get(srv.URL + "/rc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	if line != "first\n" {
		t.Fatalf("got %q", line)
	}
	close(release)
}

func TestObserverUnwrapReturnsUnderlyingWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	o := &statusObserver{ResponseWriter: rec}
	if o.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap must return the underlying writer")
	}
}

func TestObserverFlushRecordsImplicitStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	o := &statusObserver{ResponseWriter: rec}
	o.Flush()
	if !rec.Flushed || o.status() != http.StatusOK || !o.wroteHeader {
		t.Fatalf("flush must delegate and pin the implicit 200 (flushed=%v status=%d)", rec.Flushed, o.status())
	}
}

func TestObserverHijackUnsupportedWriter(t *testing.T) {
	o := &statusObserver{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := o.Hijack(); err != http.ErrNotSupported {
		t.Fatalf("a non-hijackable writer must answer http.ErrNotSupported, got %v", err)
	}
}

func hijackUpgrade(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\n"))
	rd := bufio.NewReader(conn)
	status, err := rd.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 101") {
		t.Fatalf("expected the hijacked 101 handshake, got %q err %v", status, err)
	}
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	payload, err := rd.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("ping\n"))
	echo, err := rd.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return payload + echo
}

func hijackHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the wrapped writer must expose http.Hijacker")
			return
		}
		conn, rw, err := h.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\nhello\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n')
		_, _ = rw.WriteString("echo:" + line)
		_ = rw.Flush()
	}
}

func TestObserverHijackThroughRealServer(t *testing.T) {
	srv := startGuarded(t, nil, hijackHandler(t))
	if got := hijackUpgrade(t, srv); got != "hello\necho:ping\n" {
		t.Fatalf("raw hijack exchange: %q", got)
	}
}

func TestObserverHijackLeftAloneWithResponseModifier(t *testing.T) {
	srv := startGuarded(t, modifierConfig, hijackHandler(t))
	if got := hijackUpgrade(t, srv); got != "hello\necho:ping\n" {
		t.Fatalf("hijack with a CustomResponseModifier must not be released over: %q", got)
	}
}

func TestObserverHeldWriterStillAppliesModifierAfterFlush(t *testing.T) {
	srv := startGuarded(t, modifierConfig, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("part1,"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("part2"))
	})
	resp, err := http.Get(srv.URL + "/held")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if resp.Header.Get("X-Modified") != "yes" || string(buf[:n]) != "part1,part2" {
		t.Fatalf("held response must be modified and complete, got %q header %q", buf[:n], resp.Header.Get("X-Modified"))
	}
}
