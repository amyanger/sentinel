package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinel/collector/internal/auth"
	"sentinel/collector/internal/config"
	"sentinel/collector/internal/ingest"
	"sentinel/collector/internal/query"
	"sentinel/collector/internal/store"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to collector TOML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return errors.New("--config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	s, err := store.OpenSQLite(cfg.Storage.SQLitePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	ks := auth.NewKeyStore()
	for name, key := range cfg.Clients {
		ks.Add(name, key)
	}
	slog.Info("keys loaded", "count", len(cfg.Clients))

	mux := http.NewServeMux()
	mux.Handle("/v1/events", ingestOrQuery(s, ks))
	mux.Handle("/v1/events/", query.New(s, ks))
	mux.HandleFunc("/v1/healthz", handleHealthz)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("collector listening", "addr", cfg.Server.Listen, "tls", cfg.Server.TLSCert != "")
		if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
			errCh <- srv.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey)
		} else {
			// Plain HTTP is allowed ONLY for tests and local dev. Production
			// deployments should always provide a cert; the client will refuse
			// to fall back to plaintext.
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// ingestOrQuery dispatches POST to ingest and GET to query, both at the
// exact path "/v1/events".
func ingestOrQuery(s store.Store, ks *auth.KeyStore) http.Handler {
	ingestH := ingest.New(s, ks)
	queryH := query.New(s, ks)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ingestH.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet {
			queryH.ServeHTTP(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version,
	})
}
