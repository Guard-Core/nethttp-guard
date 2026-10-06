package nethttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

const DefaultMaxBodyBytes int64 = 262144

type routeIDContextKey struct{}

func WithRouteID(ctx context.Context, routeID string) context.Context {
	return context.WithValue(ctx, routeIDContextKey{}, routeID)
}

type requestShim struct {
	req      *http.Request
	state    guardcore.RequestState
	maxBytes int64
	origBody io.Closer

	mu        sync.Mutex
	cache     []byte
	source    io.Reader
	replayPos int
}

var _ guardcore.Request = (*requestShim)(nil)

func newRequestShim(r *http.Request, maxBodyBytes int64) *requestShim {
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	shim := &requestShim{req: r, maxBytes: maxBodyBytes}
	if r.Body != nil {
		shim.origBody = r.Body
		shim.source = r.Body
		r.Body = &replayBody{shim: shim}
	}
	if routeID, ok := r.Context().Value(routeIDContextKey{}).(string); ok {
		shim.state.GuardRouteID = routeID
	}
	return shim
}

func (s *requestShim) URLPath() string { return s.req.URL.Path }

func (s *requestShim) URLScheme() string {
	if s.req.TLS != nil {
		return "https"
	}
	return "http"
}

func (s *requestShim) URLFull() string {
	full := s.URLScheme() + "://" + s.req.Host + s.req.URL.Path
	if s.req.URL.RawQuery != "" {
		full += "?" + s.req.URL.RawQuery
	}
	return full
}

func (s *requestShim) URLReplaceScheme(scheme string) string {
	full := s.URLFull()
	if scheme == "" {
		return full
	}
	return scheme + "://" + strings.TrimPrefix(strings.TrimPrefix(full, "http://"), "https://")
}

func (s *requestShim) Method() string {
	if s.req.Method == "" {
		return "GET"
	}
	return strings.ToUpper(s.req.Method)
}

func (s *requestShim) ClientHost() string {
	host, _, err := net.SplitHostPort(s.req.RemoteAddr)
	if err != nil {
		return s.req.RemoteAddr
	}
	return host
}

func (s *requestShim) Headers() guardcore.Headers {
	headers := guardcore.NewHeaders()
	for name, values := range s.req.Header {
		if len(values) > 0 {
			// Multi-line headers join with ", " like the reference
			// adapter's _join_repeated_header_lines: an X-Forwarded-For
			// chain split across repeated header lines is one chain.
			headers.Set(name, strings.Join(values, ", "))
		}
	}
	if s.req.Host != "" {
		headers.Set("Host", s.req.Host)
	}
	return headers
}

func (s *requestShim) QueryParams() map[string]string {
	values := s.req.URL.Query()
	params := make(map[string]string, len(values))
	for key, parsed := range values {
		if len(parsed) > 0 {
			params[key] = parsed[0]
		}
	}
	return params
}

func (s *requestShim) Body() ([]byte, error) {
	return s.ReadBodyPrefix(int(s.maxBytes))
}

func (s *requestShim) State() *guardcore.RequestState { return &s.state }

func (s *requestShim) ReadBodyPrefix(maxBytes int) ([]byte, error) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	if int64(maxBytes) > s.maxBytes {
		maxBytes = int(s.maxBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.fillCacheLocked(maxBytes)
	return s.cache, err
}

func (s *requestShim) fillCacheLocked(maxBytes int) error {
	for len(s.cache) < maxBytes && s.source != nil {
		buf := make([]byte, maxBytes-len(s.cache))
		n, err := s.source.Read(buf)
		if n > 0 {
			s.cache = append(s.cache, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.source = nil
				return nil
			}
			return err
		}
		if n == 0 {
			return nil
		}
	}
	return nil
}

func (s *requestShim) replayRead(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replayPos < len(s.cache) {
		n := copy(p, s.cache[s.replayPos:])
		s.replayPos += n
		return n, nil
	}
	if s.source == nil {
		return 0, io.EOF
	}
	n, err := s.source.Read(p)
	s.replayPos += n
	if errors.Is(err, io.EOF) {
		s.source = nil
	}
	return n, err
}

type replayBody struct {
	shim *requestShim
}

func (b *replayBody) Read(p []byte) (int, error) {
	return b.shim.replayRead(p)
}

func (b *replayBody) Close() error {
	if b.shim.origBody == nil {
		return nil
	}
	return b.shim.origBody.Close()
}
