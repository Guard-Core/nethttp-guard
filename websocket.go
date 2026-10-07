package nethttp

import (
	"net"
	"net/http"
	"strings"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// The websocket handshake guard, ported from fastapi-guard guard/websocket.py
// (guard_websocket / make_guard_websocket): the reference HTTP middleware
// never sees websocket connections (Starlette routes them separately), so
// the guard runs as an explicit dependency in the websocket handler before
// the upgrade. In net/http the upgrade request is a plain request the app's
// websocket handler owns: call GuardWebSocket before upgrading and reject
// the handshake when it answers a close reason (a rejected upgrade has no
// websocket to close, so the reason maps onto an HTTP status through
// WebSocketHTTPStatus; a handler that already accepted can close with the
// reason's code and reason string verbatim).

// GuardWebSocket runs the engine's websocket handshake checks over the
// upgrade request: identity resolution, the fail-secure unknown-address
// close, the ban check, the is_ip_allowed verdict, the ws rate limit, and
// the penetration detection pass sharing the HTTP pipeline's suspicious
// counts. A nil result allows the upgrade; a non-nil reason closes it. A
// nil engine fails closed with the security-check-failed reason.
func GuardWebSocket(engine *guardcore.Engine, r *http.Request) *guardcore.WebSocketCloseReason {
	if engine == nil {
		reason := guardcore.WSCloseSecurityCheckFailed
		return &reason
	}
	return engine.GuardWebSocket(newWSRequestShim(r))
}

// WebSocketHTTPStatus maps a close reason onto the HTTP status an upgrade
// rejection carries: 503 for the try-again-later security-check failure,
// 403 for every policy-violation reason, 200 for a nil (allowed) verdict.
func WebSocketHTTPStatus(reason *guardcore.WebSocketCloseReason) int {
	if reason == nil {
		return http.StatusOK
	}
	if reason.Code == guardcore.WebSocketCloseTryAgainLater {
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

// wsRequestShim mirrors the reference _WebSocketGuardRequest: method
// "WEBSOCKET", an empty body, repeated headers joined with ", "
// (_join_repeated_header_lines), and a fresh request state.
type wsRequestShim struct {
	req   *http.Request
	state guardcore.RequestState
}

func newWSRequestShim(r *http.Request) *wsRequestShim {
	return &wsRequestShim{req: r}
}

func (s *wsRequestShim) URLPath() string { return s.req.URL.Path }

func (s *wsRequestShim) URLScheme() string {
	if s.req.TLS != nil {
		return "https"
	}
	return "http"
}

func (s *wsRequestShim) URLFull() string {
	full := s.URLScheme() + "://" + s.req.Host + s.req.URL.Path
	if s.req.URL.RawQuery != "" {
		full += "?" + s.req.URL.RawQuery
	}
	return full
}

func (s *wsRequestShim) URLReplaceScheme(scheme string) string {
	full := s.URLFull()
	if scheme == "" {
		return full
	}
	return scheme + "://" + strings.TrimPrefix(strings.TrimPrefix(full, "http://"), "https://")
}

func (s *wsRequestShim) Method() string { return "WEBSOCKET" }

func (s *wsRequestShim) ClientHost() string {
	host, _, err := net.SplitHostPort(s.req.RemoteAddr)
	if err != nil {
		return s.req.RemoteAddr
	}
	return host
}

func (s *wsRequestShim) Headers() guardcore.Headers {
	headers := guardcore.NewHeaders()
	for name, values := range s.req.Header {
		if len(values) > 0 {
			headers.Set(name, strings.Join(values, ", "))
		}
	}
	if s.req.Host != "" {
		headers.Set("Host", s.req.Host)
	}
	return headers
}

func (s *wsRequestShim) QueryParams() map[string]string {
	values := s.req.URL.Query()
	params := make(map[string]string, len(values))
	for key, parsed := range values {
		if len(parsed) > 0 {
			params[key] = parsed[0]
		}
	}
	return params
}

func (s *wsRequestShim) Body() ([]byte, error) { return nil, nil }

func (s *wsRequestShim) State() *guardcore.RequestState { return &s.state }
