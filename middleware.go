package nethttp

import (
	"errors"
	"fmt"
	"log"
	"net/http"

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
		headers := m.engine.ResponseHeaders()
		for name, value := range m.engine.CORSResponseHeaders(req) {
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
		// handler ran: return rules never modify the response.
		capture := m.newBodyCapture()
		observed := &statusObserver{ResponseWriter: w, capture: capture}
		next.ServeHTTP(observed, r)
		m.engine.ProcessResponse(req, &guardcore.Response{
			StatusCode: observed.status(),
			Headers:    map[string]string{},
			Body:       observed.body(),
		})
	})
}

// statusObserver wraps the net/http ResponseWriter to record the status
// code (defaulting to the implicit 200) and the leading response body bytes.
type statusObserver struct {
	http.ResponseWriter
	capture     *bodyCapture
	wroteHeader bool
	statusCode  int
}

func (o *statusObserver) WriteHeader(code int) {
	if !o.wroteHeader {
		o.statusCode = code
		o.wroteHeader = true
	}
	o.ResponseWriter.WriteHeader(code)
}

func (o *statusObserver) Write(p []byte) (int, error) {
	if !o.wroteHeader {
		o.statusCode = http.StatusOK
		o.wroteHeader = true
	}
	if o.capture != nil {
		o.capture.record(p)
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
