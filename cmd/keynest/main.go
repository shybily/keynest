package main

import (
	"log/slog"
	"os"
	"strings"

	"github.com/shybily/keynest/internal/server"
	"github.com/shybily/keynest/internal/store"
)

var version = "0.3.1"

func main() {
	dbPath := envOr("KEYNEST_DB", "data/keynest.db")
	adminPassword := os.Getenv("KEYNEST_ADMIN_PASSWORD")
	authSecret := os.Getenv("KEYNEST_AUTH_SECRET")
	encryptionSecret := os.Getenv("KEYNEST_ENCRYPTION_KEY")
	if adminPassword == "" || authSecret == "" || encryptionSecret == "" {
		slog.Error("required environment variables are not set",
			"event", "startup_failed",
			"missing", "KEYNEST_ADMIN_PASSWORD, KEYNEST_AUTH_SECRET and KEYNEST_ENCRYPTION_KEY")
		os.Exit(1)
	}
	if len(authSecret) < 32 {
		slog.Error("auth secret is too short", "event", "startup_failed")
		os.Exit(1)
	}

	repository, err := store.Open(dbPath, encryptionSecret)
	if err != nil {
		slog.Error("failed to open database", "event", "startup_failed", "error", err)
		os.Exit(1)
	}
	defer repository.Close()

	address := envOr("KEYNEST_ADDR", ":8080")
	trustedProxies := strings.Split(os.Getenv("KEYNEST_TRUSTED_PROXIES"), ",")
	slog.Info("Keynest starting", "event", "startup", "version", version, "address", address, "database", dbPath)
	app, err := server.NewWithOptions(repository, adminPassword, authSecret, slog.Default(), trustedProxies)
	if err != nil {
		slog.Error("failed to initialize server", "event", "startup_failed", "error", err)
		os.Exit(1)
	}
	if err := app.Listen(address); err != nil {
		slog.Error("server stopped", "event", "server_failed", "address", address, "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
