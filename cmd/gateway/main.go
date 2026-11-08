package main

import (
	"context"
	"errors"
	"github.com/ATLURI0001/mcp-authz-proxy/internal/auth"
	"github.com/ATLURI0001/mcp-authz-proxy/internal/gateway"
	"github.com/ATLURI0001/mcp-authz-proxy/internal/store"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("startup or server failure", "error", err)
		os.Exit(1)
	}
}
func run() error {
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		path = "configs/local.json"
	}
	c, err := gateway.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	db, err := store.Open(ctx, os.Getenv("DATABASE_URL"), os.Getenv("REDIS_URL"))
	cancel()
	if err != nil {
		return err
	}
	defer db.Close()
	g := gateway.New(c, &auth.JWT{Issuer: c.Issuer, Audience: c.Resource, JWKSURL: c.JWKSURL}, db)
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	metrics := os.Getenv("METRICS_ADDR")
	if metrics == "" {
		metrics = "127.0.0.1:9090"
	}
	servers := []*http.Server{
		{Addr: addr, Handler: g.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 25 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384},
		{Addr: metrics, Handler: g.Metrics(), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second},
	}
	errs := make(chan error, 2)
	for _, s := range servers {
		go func() {
			err := s.ListenAndServe()
			if !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
	}
	stop, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	slog.Info("gateway ready", "address", addr, "protocol", gateway.Version)
	select {
	case <-stop.Done():
	case err = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	return err
}
