package main

import (
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/segmentio/encoding/json"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/hatemosphere/pulumi-backend/internal/api"
	"github.com/hatemosphere/pulumi-backend/internal/config"
	"github.com/hatemosphere/pulumi-backend/internal/engine"
	"github.com/hatemosphere/pulumi-backend/internal/storage"
)

// --- Servers ---

func configureACME(httpServer *http.Server, store *storage.SQLiteStore, cfg *config.Config) {
	m := &autocert.Manager{
		Cache:      storage.NewACMECache(store),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.ACMEDomain),
		Email:      cfg.ACMEEmail,
	}
	if cfg.ACMECA != "" {
		m.Client = &acme.Client{DirectoryURL: cfg.ACMECA}
	}
	httpServer.TLSConfig = m.TLSConfig()

	go func() {
		challengeServer := &http.Server{
			Addr:              ":80",
			Handler:           m.HTTPHandler(nil),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
		}
		slog.Info("ACME HTTP-01 challenge server starting", "addr", ":80", "domain", cfg.ACMEDomain)
		if err := challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("ACME challenge server error", "error", err)
		}
	}()

	slog.Info("ACME automatic TLS enabled", "domain", cfg.ACMEDomain, "cache", "sqlite")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(v)
}

func startManagementServer(mgr *engine.Manager, cfg *config.Config) *http.Server {
	if cfg.ManagementAddr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := mgr.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /metrics", api.MetricsHandler())

	if cfg.PprofEnabled {
		mux.HandleFunc("GET /debug/pprof/", pprof.Index)
		mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
		slog.Info("pprof enabled on management server")
	}

	srv := &http.Server{
		Addr:              cfg.ManagementAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		slog.Info("management server starting", "addr", cfg.ManagementAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("management server error", "error", err)
		}
	}()

	return srv
}

func listenAndServe(srv *http.Server, cfg *config.Config) error {
	switch {
	case cfg.ACMEDomain != "":
		return srv.ListenAndServeTLS("", "")
	case cfg.TLS:
		return srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	default:
		return srv.ListenAndServe()
	}
}
