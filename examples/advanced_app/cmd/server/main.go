// Command server assembles the advanced example: tuned engine config, route
// registry, the nethttp-guard adapter, and graceful shutdown.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"

	"github.com/rennf93/nethttp-guard/examples/advanced_app/internal/config"
	"github.com/rennf93/nethttp-guard/examples/advanced_app/internal/server"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	// Route registry: the route-ID middleware in internal/server attaches
	// the "admin" ID to /admin/* requests and the engine resolves this
	// config. RequiredHeaders is engine-enforced: missing or mismatched
	// token requests are rejected before the handlers run. The pipeline
	// consumes the other route-scoped knobs too (rate limits, IP
	// allowlists/blocklists, RequireHTTPS, MaxRequestSize,
	// AllowedContentTypes, authentication).
	adminToken := envOr("ADMIN_TOKEN", "admin-token-change-me")
	engine.Routes.Register("admin", func(rc *guardcore.RouteConfig) {
		rc.RequiredHeaders = guardcore.RequiredHeaders{
			{Name: "X-Admin-Token", Value: adminToken},
		}
	})

	handler, err := server.New(engine, map[string]string{
		"/admin/": "admin",
	})
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Println("advanced example listening on :8080 (nginx fronts this in compose)")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
