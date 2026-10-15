package nethttp

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const failClosedMessage = "Security check failed"

type middleware struct {
	engine   *guardcore.Engine
	maxBytes int64
	logger   *log.Logger
}

type Option func(*middleware)

func WithMaxBodyBytes(maxBodyBytes int64) Option {
	return func(m *middleware) {
		if maxBodyBytes > 0 {
			m.maxBytes = maxBodyBytes
		}
	}
}

func WithLogger(logger *log.Logger) Option {
	return func(m *middleware) {
		if logger != nil {
			m.logger = logger
		}
	}
}

func New(engine *guardcore.Engine, opts ...Option) (func(http.Handler) http.Handler, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}
	m := &middleware{engine: engine, maxBytes: DefaultMaxBodyBytes, logger: log.Default()}
	for _, opt := range opts {
		opt(m)
	}
	return m.wrap, nil
}

func (m *middleware) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := newRequestShim(r, m.maxBytes)
		verdict, err := m.check(req)
		if err != nil {
			m.logger.Printf("guardcore nethttp: engine malfunction, failing closed: %v", err)
			applyResponse(w, m.engine.CreateErrorResponse(500, failClosedMessage))
			return
		}
		if verdict != nil {
			applyResponse(w, verdict)
			return
		}
		// Security headers on the pass-through path: the engine computes the
		// set (blocked verdicts already carry it), the adapter applies it
		// before the handler writes its response. CORS response headers are
		// merged on top (the reference _inject_cors_headers runs after the
		// security-header set, so CORS wins on a shared name) whenever the
		// request carries an Origin and CORS is enabled.
		cors := m.engine.CORSResponseHeaders(req)
		headers := m.engine.ResponseHeaders()
		for name, value := range cors {
			headers[name] = value
		}
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		// Behavioral return rules (route and global) run against the
		// response the handler produced, exactly like the reference
		// response factory's behavioral phase. The adapter captures the
		// leading response body up to the configured inspect budget and
		// hands status code plus captured prefix to the engine after the
		// handler ran: return rules never modify the response. With a
		// CustomResponseModifier configured the whole response is held
		// instead, so the modifier (the last step of the reference
		// process_response) can rewrite it before it is sent.
		capture := m.newBodyCapture()
		observed := &statusObserver{ResponseWriter: w, capture: capture,
			hold: m.engine.Config.CustomResponseModifier != nil}
		next.ServeHTTP(observed, r)
		if observed.hijacked {
			// The handler took over the connection (websocket upgrade, raw
			// stream): nothing is left to observe, modify or write.
			return
		}
		m.engine.ProcessResponse(req, &guardcore.Response{
			StatusCode: observed.status(),
			Headers:    map[string]string{},
			Body:       observed.body(),
		})
		if observed.hold {
			observed.release(m.engine, cors)
		}
	})
}

// statusObserver wraps the net/http ResponseWriter to record the status
// code (defaulting to the implicit 200) and the leading response body bytes.
// In hold mode it also buffers the whole response (status, body) until
// release, so the engine's CustomResponseModifier can rewrite it.
type statusObserver struct {
	http.ResponseWriter
	capture     *bodyCapture
	wroteHeader bool
	statusCode  int
	hold        bool
	held        []byte
	hijacked    bool
}

// Unwrap exposes the underlying writer so http.ResponseController reaches
// the optional interfaces (deadlines, full duplex, ...) the observer does
// not wrap itself.
func (o *statusObserver) Unwrap() http.ResponseWriter { return o.ResponseWriter }

// Flush implements http.Flusher. In pass-through mode it pins the implicit
// 200 the real writer is about to send and delegates. In hold mode the
// response is buffered for the CustomResponseModifier (which must see all
// of it), so Flush is a no-op there and the response is sent at release.
func (o *statusObserver) Flush() {
	if o.hold || o.hijacked {
		return
	}
	if !o.wroteHeader {
		o.statusCode = http.StatusOK
		o.wroteHeader = true
	}
	if f, ok := o.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker by delegating to the underlying writer.
// A hijacked connection is left alone: the middleware neither releases a
// held response nor runs the response pass over it.
func (o *statusObserver) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := o.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		o.hijacked = true
	}
	return conn, rw, err
}

func (o *statusObserver) WriteHeader(code int) {
	if !o.wroteHeader {
		o.statusCode = code
		o.wroteHeader = true
	}
	if !o.hold {
		o.ResponseWriter.WriteHeader(code)
	}
}

func (o *statusObserver) Write(p []byte) (int, error) {
	if !o.wroteHeader {
		o.statusCode = http.StatusOK
		o.wroteHeader = true
	}
	if o.capture != nil {
		o.capture.record(p)
	}
	if o.hold {
		o.held = append(o.held, p...)
		return len(p), nil
	}
	return o.ResponseWriter.Write(p)
}

func (o *statusObserver) status() int {
	if !o.wroteHeader {
		return http.StatusOK
	}
	return o.statusCode
}

func (o *statusObserver) body() []byte {
	if o.capture == nil {
		return nil
	}
	return o.capture.buf
}

// release runs the modifier over the held response and writes the result to
// the real writer. Headers the modifier did not touch keep every value
// (Set-Cookie and friends); changed or added ones are set, removed ones are
// deleted. CORS headers are applied again after the modifier, as the
// reference dispatch injects them on the processed response.
func (o *statusObserver) release(engine *guardcore.Engine, cors map[string]string) {
	header := o.ResponseWriter.Header()
	resp := &guardcore.Response{StatusCode: o.status(), Headers: headerSnapshot(header), Body: o.held}
	before := make(map[string]string, len(resp.Headers))
	for name, value := range resp.Headers {
		before[name] = value
	}
	out := engine.ModifyResponse(resp)
	for name := range before {
		if _, kept := out.Headers[name]; !kept {
			header.Del(name)
		}
	}
	for name, value := range out.Headers {
		if prev, seen := before[name]; !seen || prev != value {
			header.Set(name, value)
		}
	}
	if header.Get("Content-Length") != "" {
		header.Set("Content-Length", strconv.Itoa(len(out.Body)))
	}
	for name, value := range cors {
		header.Set(name, value)
	}
	o.ResponseWriter.WriteHeader(out.StatusCode)
	if len(out.Body) > 0 {
		_, _ = o.ResponseWriter.Write(out.Body)
	}
}

func headerSnapshot(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		if len(values) > 0 {
			out[name] = values[0]
		}
	}
	return out
}

// bodyCapture records the leading bytes of the pass-through response body,
// bounded by the engine's behavior_max_response_body_inspect_bytes budget,
// and only when behavior_scan_response_body is enabled (with the flag off
// the engine rejects every rule that would need the body, so there is
// nothing to inspect).
type bodyCapture struct {
	budget int
	buf    []byte
}

func (m *middleware) newBodyCapture() *bodyCapture {
	if !m.engine.Config.BehaviorScanResponseBody {
		return nil
	}
	budget := m.engine.Config.BehaviorMaxResponseBodyInspectBytes
	if budget <= 0 {
		return nil
	}
	return &bodyCapture{budget: budget}
}

func (c *bodyCapture) record(p []byte) {
	if remaining := c.budget - len(c.buf); remaining > 0 {
		if len(p) < remaining {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:remaining]...)
		}
	}
}

func (m *middleware) check(req guardcore.Request) (verdict *guardcore.Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine panic: %v", r)
		}
	}()
	return m.engine.Check(req), nil
}

func applyResponse(w http.ResponseWriter, response *guardcore.Response) {
	for name, value := range response.Headers {
		w.Header().Set(name, value)
	}
	w.WriteHeader(response.StatusCode)
	if len(response.Body) > 0 {
		_, _ = w.Write(response.Body)
	}
}
