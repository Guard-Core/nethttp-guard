package nethttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rennf93/guard-core-go/v4/guardcore"
)

// fakeGeoResolver is a foreign CountryResolver carrying the optional
// get_status surface the status route picks up (the built-in GeoIPManager's
// GetStatus shape).
type fakeGeoResolver struct {
	status map[string]any
}

func (f *fakeGeoResolver) GetCountry(ip string) (string, bool) { return "", false }

func (f *fakeGeoResolver) GetStatus() map[string]any { return f.status }

func statusServer(t *testing.T, mutate func(*guardcore.SecurityConfig), path string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	engine := newTestEngine(t, mutate)
	mux := http.NewServeMux()
	if err := AddStatusRoute(mux, engine, path); err != nil {
		t.Fatalf("add status route: %v", err)
	}
	served := path
	if served == "" {
		served = DefaultStatusPath
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", served, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status route must answer 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("status route must serve application/json, got %q", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("status payload must be JSON: %v", err)
	}
	return rec, payload
}

func TestAddStatusRouteNilEngineRejected(t *testing.T) {
	if err := AddStatusRoute(http.NewServeMux(), nil, ""); err == nil {
		t.Fatal("nil engine must be rejected")
	}
	if _, err := NewStatusHandler(nil); err == nil {
		t.Fatal("nil engine must be rejected")
	}
}

func TestAddStatusRouteNilMuxRejected(t *testing.T) {
	engine := newTestEngine(t, nil)
	if err := AddStatusRoute(nil, engine, ""); err == nil {
		t.Fatal("nil mux must be rejected")
	}
}

func TestStatusRouteDefaultPath(t *testing.T) {
	_, payload := statusServer(t, nil, "")
	if _, ok := payload["cloud_providers"]; !ok {
		t.Fatal("payload must carry cloud_providers")
	}
}

func TestStatusRouteCustomPath(t *testing.T) {
	_, payload := statusServer(t, nil, "/health/guard")
	if _, ok := payload["geo_ip"]; !ok {
		t.Fatal("payload must carry geo_ip")
	}
}

func TestStatusRouteGetOnly(t *testing.T) {
	engine := newTestEngine(t, nil)
	mux := http.NewServeMux()
	if err := AddStatusRoute(mux, engine, ""); err != nil {
		t.Fatalf("add status route: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", DefaultStatusPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST must not reach the status handler, got %d", rec.Code)
	}
}

func TestStatusRouteCloudProvidersPayload(t *testing.T) {
	_, payload := statusServer(t, nil, "")
	raw, ok := payload["cloud_providers"].(map[string]any)
	if !ok {
		t.Fatal("cloud_providers must be an object")
	}
	if len(raw) == 0 {
		t.Fatal("cloud_providers must list the reference provider table")
	}
	for provider, entry := range raw {
		row, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("provider %s must be an object", provider)
		}
		if ready, ok := row["ready"].(bool); !ok || ready {
			t.Fatalf("provider %s must report ready=false before any refresh", provider)
		}
		if entries, ok := row["entries"].(float64); !ok || entries != 0 {
			t.Fatalf("provider %s must report entries=0 before any refresh, got %v", provider, entries)
		}
		if refreshed, ok := row["last_refreshed"]; !ok || refreshed != nil {
			t.Fatalf("provider %s must report last_refreshed=null before any refresh, got %v", provider, refreshed)
		}
	}
}

func TestStatusRouteGeoIPNullWithoutHandler(t *testing.T) {
	_, payload := statusServer(t, nil, "")
	if got, ok := payload["geo_ip"]; !ok || got != nil {
		t.Fatalf("geo_ip must be null without a configured handler, got %v", got)
	}
}

func TestStatusRouteGeoIPHandlerStatus(t *testing.T) {
	stub := &fakeGeoResolver{status: map[string]any{
		"ready":          true,
		"last_refreshed": "2026-10-06T00:00:00Z",
		"entries":        7,
	}}
	_, payload := statusServer(t, func(cfg *guardcore.SecurityConfig) {
		cfg.GeoIPHandler = stub
	}, "")
	geo, ok := payload["geo_ip"].(map[string]any)
	if !ok {
		t.Fatalf("geo_ip must serve the handler's get_status snapshot, got %v", payload["geo_ip"])
	}
	if ready, ok := geo["ready"].(bool); !ok || !ready {
		t.Fatalf("geo_ip.ready must pass the handler snapshot through, got %v", geo["ready"])
	}
	if entries, ok := geo["entries"].(float64); !ok || entries != 7 {
		t.Fatalf("geo_ip.entries must pass the handler snapshot through, got %v", geo["entries"])
	}
}

func TestStatusRouteRedisDisabled(t *testing.T) {
	_, payload := statusServer(t, nil, "")
	redis, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatal("redis must be an object")
	}
	if enabled, ok := redis["enabled"].(bool); !ok || enabled {
		t.Fatalf("redis.enabled must mirror the config, got %v", redis["enabled"])
	}
	if ok, _ := redis["ok"].(bool); !ok {
		t.Fatalf("redis.ok must default true while disabled, got %v", redis["ok"])
	}
	if err, ok := redis["error"]; !ok || err != nil {
		t.Fatalf("redis.error must be null while disabled, got %v", err)
	}
}

func TestStatusRouteRedisUnreachable(t *testing.T) {
	// A refused dial fails immediately (no dial-timeout wait); the lazy
	// probe reports the failure instead of pretending to be healthy.
	_, payload := statusServer(t, func(cfg *guardcore.SecurityConfig) {
		cfg.EnableRedis = true
		cfg.RedisURL = "redis://127.0.0.1:1/0"
	}, "")
	redis, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatal("redis must be an object")
	}
	if enabled, ok := redis["enabled"].(bool); !ok || !enabled {
		t.Fatalf("redis.enabled must mirror the config, got %v", redis["enabled"])
	}
	if ok, _ := redis["ok"].(bool); ok {
		t.Fatalf("redis.ok must be false when the probe cannot reach redis, got %v", redis)
	}
	if err, ok := redis["error"].(string); !ok || err == "" {
		t.Fatalf("redis.error must carry the probe failure, got %v", redis["error"])
	}
}

func TestStatusHandlerDirect(t *testing.T) {
	engine := newTestEngine(t, nil)
	handler, err := NewStatusHandler(engine)
	if err != nil {
		t.Fatalf("new status handler: %v", err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/anywhere", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handler must answer 200 on any mount, got %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Body.String(), "{") {
		t.Fatalf("handler must serve a JSON object, got %q", rec.Body.String())
	}
}
