package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/shybily/keynest/internal/config"
)

func TestCloudflareConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  CloudflareConfig
		wantErr bool
	}{
		{
			name:   "valid",
			config: CloudflareConfig{Enabled: true, APIToken: "token", ZoneID: "zone", PublicURL: "https://keynest.example"},
		},
		{
			name:    "missing token",
			config:  CloudflareConfig{Enabled: true, ZoneID: "zone", PublicURL: "https://keynest.example"},
			wantErr: true,
		},
		{
			name:    "insecure public URL",
			config:  CloudflareConfig{Enabled: true, APIToken: "token", ZoneID: "zone", PublicURL: "http://keynest.example"},
			wantErr: true,
		},
		{
			name:    "public URL query",
			config:  CloudflareConfig{Enabled: true, APIToken: "token", ZoneID: "zone", PublicURL: "https://keynest.example/?token=secret"},
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := validateCloudflareConfig(test.config) != ""
			if got != test.wantErr {
				t.Fatalf("validateCloudflareConfig() error=%v, want %v", got, test.wantErr)
			}
		})
	}
}

func TestCloudflareClientVerifyAndPurge(t *testing.T) {
	var purged []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization header = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/user/tokens/verify":
			_, _ = writer.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		case request.Method == http.MethodGet && request.URL.Path == "/zones/test-zone":
			_, _ = writer.Write([]byte(`{"success":true,"result":{"status":"active"}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/zones/test-zone/purge_cache":
			var body struct {
				Files []string `json:"files"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode purge body: %v", err)
			}
			purged = body.Files
			_, _ = writer.Write([]byte(`{"success":true}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client := &cloudflareClient{
		token:      "test-token",
		zoneID:     "test-zone",
		httpClient: server.Client(),
		apiBaseURL: server.URL,
	}
	if err := client.verify(context.Background()); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
	files := []string{"https://keynest.example/api/v1/configs/demo/prod/api"}
	if err := client.purge(context.Background(), files); err != nil {
		t.Fatalf("purge() error = %v", err)
	}
	if !reflect.DeepEqual(purged, files) {
		t.Fatalf("purged files = %#v, want %#v", purged, files)
	}
}

func TestCDNRetryDelayIsBounded(t *testing.T) {
	if got := cdnRetryDelay(1); got != 5*time.Second {
		t.Fatalf("first retry delay = %s, want 5s", got)
	}
	if got := cdnRetryDelay(20); got != time.Hour {
		t.Fatalf("maximum retry delay = %s, want 1h", got)
	}
}

func TestPurgeFilesTargetsConfigAndRenderEndpoints(t *testing.T) {
	controller := &cdnController{config: CloudflareConfig{PublicURL: "https://keynest.example/base/"}}
	files := controller.purgeFiles(config.Address{Project: "demo", Environment: "prod", Service: "api"})
	want := []string{
		"https://keynest.example/base/api/v1/configs/demo/prod/api",
		"https://keynest.example/base/api/v1/configs/demo/prod/api/render/env",
		"https://keynest.example/base/api/v1/configs/demo/prod/api/render/yaml",
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("purgeFiles() = %#v, want %#v", files, want)
	}
}
