package nethttp

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// WebSocket guard, ported from fastapi-guard guard/websocket.py: an
// upgrade request runs the standard guard checks and a blocked handshake
// is rejected with the reference's close shapes - the (code, reason)
// pairs of guard_websocket - carried on a 403 handshake response through
// dedicated headers (net/http has no websocket-close frame before the
// handshake completes; this is the HTTP-level translation of Starlette's
// WebSocketException denial).

// WebSocket close codes the reference pins.
const (
	// WebSocketClosePolicyViolation is WS_1008_POLICY_VIOLATION.
	WebSocketClosePolicyViolation = 1008
	// WebSocketCloseTryAgainLater is WS_1013_TRY_AGAIN_LATER.
	WebSocketCloseTryAgainLater = 1013
)

// WebSocketCloseReason is one of the reference's close shapes.
type WebSocketCloseReason struct {
	Code   int
	Reason string
}

// The reference's WS_CLOSE_* table (guard/websocket.py).
var (
	WSCloseIPBanned             = WebSocketCloseReason{WebSocketClosePolicyViolation, "IP banned"}
	WSCloseIPNotAllowed         = WebSocketCloseReason{WebSocketClosePolicyViolation, "IP not allowed"}
	WSCloseRateLimitExceeded    = WebSocketCloseReason{WebSocketClosePolicyViolation, "Rate limit exceeded"}
	WSCloseClientAddressUnknown = WebSocketCloseReason{WebSocketClosePolicyViolation, "Client address could not be determined"}
	WSCloseSecurityCheckFailed  = WebSocketCloseReason{WebSocketCloseTryAgainLater, "Security check failed"}
	WSCloseSuspiciousActivity   = WebSocketCloseReason{WebSocketClosePolicyViolation, "Suspicious activity detected"}
)

// Headers carrying the close shape on the rejected handshake response.
const (
	WebSocketCloseCodeHeader   = "X-Guard-WebSocket-Close"
	WebSocketCloseReasonHeader = "X-Guard-WebSocket-Reason"
)

// IsWebSocketUpgrade answers whether the request is a WebSocket upgrade:
// an Upgrade: websocket header plus an Upgrade token in Connection
// (the token list may carry other connections, e.g.
// "keep-alive, Upgrade").
func IsWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

// wsGuardRequest is the upgrade request the engine inspects: the
// reference's _WebSocketGuardRequest pins method "WEBSOCKET" so rate
// limit keys and events never collide with HTTP routes.
type wsGuardRequest struct {
	*requestShim
}

var _ guardcore.Request = (*wsGuardRequest)(nil)

func (w *wsGuardRequest) Method() string { return "WEBSOCKET" }

// websocketCloseForVerdict maps a blocked verdict onto the reference's
// close shapes: 1013 for the detection-check-failure status, the rate
// limit close for 429, the ban closes for the ban messages the engine
// pins, and everything else the IP-not-allowed close (the reference's
// is_ip_allowed family: whitelist, blacklist, country rules).
func websocketCloseForVerdict(verdict *guardcore.Response) WebSocketCloseReason {
	switch {
	case verdict.StatusCode == http.StatusInternalServerError:
		return WSCloseSecurityCheckFailed
	case verdict.StatusCode == http.StatusTooManyRequests:
		return WSCloseRateLimitExceeded
	}
	body := strings.ToLower(string(verdict.Body))
	switch {
	case strings.Contains(body, "banned"):
		return WSCloseIPBanned
	case strings.Contains(body, "suspicious"):
		return WSCloseSuspiciousActivity
	}
	return WSCloseIPNotAllowed
}

// rejectWebSocket answers the handshake with the mapped close shape.
func (m *middleware) rejectWebSocket(w http.ResponseWriter, reason WebSocketCloseReason) {
	response := m.engine.CreateErrorResponse(http.StatusForbidden,
		"WebSocket connection rejected: "+reason.Reason)
	response.SetHeader(WebSocketCloseCodeHeader, strconv.Itoa(reason.Code))
	response.SetHeader(WebSocketCloseReasonHeader, reason.Reason)
	applyResponse(w, response)
}
