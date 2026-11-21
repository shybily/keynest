package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shybily/keynest/internal/config"
	"github.com/shybily/keynest/internal/secure"
)

func TestCustomLoggerAdapters(t *testing.T) {
	var receivedLevel LogLevel
	var receivedEvent string
	var receivedFields LogFields
	custom := LoggerFunc(func(level LogLevel, event, message string, fields LogFields) {
		receivedLevel = level
		receivedEvent = event
		receivedFields = fields
	})
	custom.Log(LogLevelWarn, "sdk_test", "test message", LogFields{"status": 503})

	if receivedLevel != LogLevelWarn || receivedEvent != "sdk_test" {
		t.Fatalf("custom logger received level=%q event=%q", receivedLevel, receivedEvent)
	}
	if receivedFields["status"] != 503 {
		t.Fatalf("custom logger fields=%v", receivedFields)
	}

	NewSlogLogger(slog.New(slog.NewTextHandler(io.Discard, nil))).Log(
		LogLevelInfo, "sdk_test", "test message", LogFields{"status": 200},
	)
}

func TestFetchAndGet(t *testing.T) {
	privatePEM, publicPEM, err := secure.GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	address := Address{Project: "project", Environment: "prod", Service: "api"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/api/v1/configs/project/prod/api" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		plain, _ := json.Marshal(Document{
			Address: address, Version: 7,
			Values: map[string]any{"http": map[string]any{"port": float64(8080)}},
		})
		envelope, err := secure.Encrypt(publicPEM, "key-1", config.Address{
			Project: address.Project, Environment: address.Environment,
			Service: address.Service,
		}, 7, plain)
		if err != nil {
			t.Errorf("encrypt test payload: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	client, err := New(server.URL, "test-token", privatePEM, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	var target struct {
		HTTP struct {
			Port int `json:"port"`
		} `json:"http"`
	}
	version, err := client.Get(context.Background(), address, &target)
	if err != nil {
		t.Fatal(err)
	}
	if version != 7 || target.HTTP.Port != 8080 {
		t.Fatalf("Get() = version %d, config %#v", version, target)
	}
}

func TestFetchUsesETagCache(t *testing.T) {
	privatePEM, publicPEM, err := secure.GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	address := Address{Project: "project", Environment: "prod", Service: "api"}
	plain, err := json.Marshal(Document{
		Address: address,
		Version: 3,
		Values:  map[string]any{"port": float64(8080)},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secure.Encrypt(publicPEM, "key-1", config.Address{
		Project:     address.Project,
		Environment: address.Environment,
		Service:     address.Service,
	}, 3, plain)
	if err != nil {
		t.Fatal(err)
	}

	var ifNoneMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ifNoneMatch = r.Header.Get("If-None-Match")
		if ifNoneMatch == `"3"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client, err := NewWithOptions(server.URL, "test-token", privatePEM, server.Client(), Options{CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	if _, err := client.Fetch(context.Background(), address); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}
	document, err := client.Fetch(context.Background(), address)
	if err != nil {
		t.Fatalf("conditional Fetch: %v", err)
	}
	if ifNoneMatch != `"3"` {
		t.Fatalf("If-None-Match = %q, want %q", ifNoneMatch, `"3"`)
	}
	if document.Version != 3 {
		t.Fatalf("document version = %d, want 3", document.Version)
	}
}

func TestFetchUsesPersistentCacheWhenCenterUnavailable(t *testing.T) {
	privatePEM, publicPEM, err := secure.GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	address := Address{Project: "project", Environment: "prod", Service: "api"}
	plain, err := json.Marshal(Document{
		Address: address, Version: 7,
		Values: map[string]any{"password": "dont-persist-this-plaintext"},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secure.Encrypt(publicPEM, "key-1", config.Address{
		Project: address.Project, Environment: address.Environment,
		Service: address.Service,
	}, 7, plain)
	if err != nil {
		t.Fatal(err)
	}

	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := int(status.Load()); code != http.StatusOK {
			http.Error(w, http.StatusText(code), code)
			return
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	client, err := NewWithOptions(server.URL, "test-token", privatePEM, server.Client(), Options{
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := client.Fetch(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Version != 7 {
		t.Fatalf("fresh version = %d, want 7", fresh.Version)
	}
	if _, err := client.Fetch(context.Background(), address); err != nil {
		t.Fatalf("refresh existing cache file: %v", err)
	}

	files, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("cache file count = %d, want 1", len(files))
	}
	cachedBytes, err := os.ReadFile(filepath.Join(cacheDir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cachedBytes), "dont-persist-this-plaintext") {
		t.Fatal("cache contains plaintext configuration")
	}

	status.Store(http.StatusServiceUnavailable)
	var fallbackCalls int
	restarted, err := NewWithOptions(server.URL, "test-token", privatePEM, server.Client(), Options{
		CacheDir: cacheDir,
		OnFallback: func(Address, error) {
			fallbackCalls++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := restarted.Fetch(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if stale.Version != 7 || stale.Values["password"] != "dont-persist-this-plaintext" {
		t.Fatalf("cached document = %#v", stale)
	}
	if fallbackCalls != 1 {
		t.Fatalf("fallback callback count = %d, want 1", fallbackCalls)
	}

	watchCtx, cancelWatch := context.WithCancel(context.Background())
	watchStarted := make(chan struct{}, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- restarted.Watch(watchCtx, address, 5*time.Millisecond, func(document Document) error {
			if document.Version != 7 {
				t.Errorf("watch document version = %d, want 7", document.Version)
			}
			watchStarted <- struct{}{}
			return nil
		})
	}()
	select {
	case <-watchStarted:
	case <-time.After(time.Second):
		cancelWatch()
		t.Fatal("Watch() did not deliver the cached configuration")
	}
	time.Sleep(25 * time.Millisecond)
	cancelWatch()
	if err := <-watchDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("Watch() error = %v, want context cancellation", err)
	}

	status.Store(http.StatusUnauthorized)
	if _, err := restarted.Fetch(context.Background(), address); err == nil {
		t.Fatal("Fetch() succeeded with an unauthorized response")
	}
	if fallbackCalls != 1 {
		t.Fatalf("unauthorized response used fallback; callback count = %d", fallbackCalls)
	}
}
