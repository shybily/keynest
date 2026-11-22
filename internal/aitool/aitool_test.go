package aitool

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shybily/keynest/internal/server"
	"github.com/shybily/keynest/internal/store"
)

const e2eSecret = "01234567890123456789012345678901"

func newE2EServer(t *testing.T) *httptest.Server {
	t.Helper()
	repository, err := store.Open(":memory:", e2eSecret)
	if err != nil {
		t.Fatal(err)
	}
	app := server.New(repository, "test-password", e2eSecret)
	if err := app.Build(); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(app)
	t.Cleanup(func() {
		httpServer.Close()
		repository.Close()
	})
	return httpServer
}

func newE2EClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	client, err := New(baseURL, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func callTool(t *testing.T, c *Client, name string, args map[string]any) (string, error) {
	t.Helper()
	tools := Tools()
	for i := range tools {
		if tools[i].Name != name {
			continue
		}
		encoded, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		value, err := tools[i].Handler(context.Background(), c, encoded)
		return FormatOutput(value), err
	}
	t.Fatalf("tool %s not found", name)
	return "", nil
}

func TestToolLifecycle(t *testing.T) {
	httpServer := newE2EServer(t)
	client := newE2EClient(t, httpServer.URL)
	ctx := context.Background()
	address := map[string]any{"project": "shop", "environment": "prod", "service": "api"}

	// Login happens lazily on first call.
	if _, err := callTool(t, client, "create_project", map[string]any{"name": "shop"}); err != nil {
		t.Fatalf("create_project: %v", err)
	}
	if _, err := callTool(t, client, "create_environment", map[string]any{"project": "shop", "name": "prod"}); err != nil {
		t.Fatalf("create_environment: %v", err)
	}
	created, err := callTool(t, client, "create_service", map[string]any{
		"project": "shop", "environment": "prod", "name": "api",
	})
	if err != nil {
		t.Fatalf("create_service: %v", err)
	}
	if !strings.Contains(created, `"token"`) {
		t.Fatalf("create_service did not return a token: %s", created)
	}

	// Import .env as a draft, then inspect it.
	if _, err := callTool(t, client, "import_draft", map[string]any{
		"project": "shop", "environment": "prod", "service": "api",
		"format": "env", "content": "APP_PORT=8080\nAPP_NAME=demo",
	}); err != nil {
		t.Fatalf("import_draft: %v", err)
	}
	draft, err := callTool(t, client, "get_draft", address)
	if err != nil {
		t.Fatalf("get_draft: %v", err)
	}
	if !strings.Contains(draft, "APP_PORT") && !strings.Contains(draft, "app.port") {
		t.Fatalf("get_draft missing imported field: %s", draft)
	}

	// Render the draft before publishing.
	rendered, err := callTool(t, client, "render_draft", map[string]any{
		"project": "shop", "environment": "prod", "service": "api", "format": "env",
	})
	if err != nil {
		t.Fatalf("render_draft: %v", err)
	}
	if !strings.Contains(rendered, "8080") {
		t.Fatalf("render_draft did not include value: %s", rendered)
	}

	// Publish and verify history + summaries.
	published, err := callTool(t, client, "publish", address)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !strings.Contains(published, `"version":1`) {
		t.Fatalf("publish did not return version 1: %s", published)
	}
	history, err := callTool(t, client, "list_history", address)
	if err != nil {
		t.Fatalf("list_history: %v", err)
	}
	if !strings.Contains(history, "version") {
		t.Fatalf("list_history returned unexpected body: %s", history)
	}
	summaries, err := callTool(t, client, "list_configs", map[string]any{})
	if err != nil {
		t.Fatalf("list_configs: %v", err)
	}
	if !strings.Contains(summaries, "shop") {
		t.Fatalf("list_configs missing project: %s", summaries)
	}
	resources, err := callTool(t, client, "list_resources", map[string]any{})
	if err != nil {
		t.Fatalf("list_resources: %v", err)
	}
	if !strings.Contains(resources, "api") {
		t.Fatalf("list_resources missing service: %s", resources)
	}

	// Standalone credential management (new endpoints in v0.4).
	keys, err := callTool(t, client, "create_key", map[string]any{
		"name": "ci", "project": "shop", "environment": "prod", "service": "api",
	})
	if err != nil {
		t.Fatalf("create_key: %v", err)
	}
	var createdKey struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal([]byte(keys), &createdKey); err != nil || createdKey.Key.ID == "" {
		t.Fatalf("create_key did not return an id: %s (%v)", keys, err)
	}
	id := createdKey.Key.ID

	rotatedToken, err := callTool(t, client, "regenerate_key_token", map[string]any{"id": id})
	if err != nil || !strings.Contains(rotatedToken, "token") {
		t.Fatalf("regenerate_key_token: %v (%s)", err, rotatedToken)
	}
	if _, err := callTool(t, client, "regenerate_key_pair", map[string]any{"id": id}); err != nil {
		t.Fatalf("regenerate_key_pair: %v", err)
	}
	viewedKey, err := callTool(t, client, "view_private_key", map[string]any{"id": id})
	if err != nil || !strings.Contains(viewedKey, "privateKey") {
		t.Fatalf("view_private_key: %v (%s)", err, viewedKey)
	}
	downloaded, err := callTool(t, client, "download_private_key", map[string]any{"id": id})
	if err != nil || !strings.Contains(downloaded, "PRIVATE KEY") {
		t.Fatalf("download_private_key: %v (%s)", err, downloaded)
	}
	if err := callToolExpectErr(t, client, "delete_key", map[string]any{"id": id}); err != nil {
		t.Fatalf("delete_key: %v", err)
	}
	_ = ctx
}

func callToolExpectErr(t *testing.T, c *Client, name string, args map[string]any) error {
	t.Helper()
	tools := Tools()
	for i := range tools {
		if tools[i].Name == name {
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tools[i].Handler(context.Background(), c, encoded)
			return err
		}
	}
	t.Fatalf("tool %s not found", name)
	return nil
}

func TestClientRejectsBadLogin(t *testing.T) {
	httpServer := newE2EServer(t)
	client, err := New(httpServer.URL, "wrong-password")
	if err != nil {
		t.Fatal(err)
	}
	_, err = callTool(t, client, "list_configs", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "login failed") {
		t.Fatalf("expected login failure, got %v", err)
	}
}

func TestClientRejectsInvalidArguments(t *testing.T) {
	httpServer := newE2EServer(t)
	client := newE2EClient(t, httpServer.URL)
	_, err := callTool(t, client, "get_draft", map[string]any{"project": "shop"})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required-field error, got %v", err)
	}
}

func TestMCPProtocol(t *testing.T) {
	httpServer := newE2EServer(t)
	client := newE2EClient(t, httpServer.URL)

	requests := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n",
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n",
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}` + "\n",
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_configs","arguments":{}}}` + "\n",
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}` + "\n",
		`{"jsonrpc":"2.0","id":5,"method":"bogus","params":{}}` + "\n",
		`not-json` + "\n",
	}
	in := strings.NewReader(strings.Join(requests, ""))
	var out bytes.Buffer
	if err := ServeMCP(context.Background(), client, in, &out); err != nil {
		t.Fatalf("ServeMCP: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 responses (notification must be silent), got %d: %s", len(lines), out.String())
	}

	var initResponse struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initResponse); err != nil {
		t.Fatal(err)
	}
	if initResponse.Result.ProtocolVersion != mcpProtocolVersion || initResponse.Result.ServerInfo.Name != "keynest" {
		t.Fatalf("unexpected initialize result: %s", lines[0])
	}

	var listResponse struct {
		Result struct {
			Tools []Tool `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResponse); err != nil {
		t.Fatal(err)
	}
	if len(listResponse.Result.Tools) < 15 {
		t.Fatalf("expected full tool catalog, got %d", len(listResponse.Result.Tools))
	}

	var callResponse struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &callResponse); err != nil {
		t.Fatal(err)
	}
	if callResponse.Result.IsError || len(callResponse.Result.Content) == 0 || callResponse.Result.Content[0].Type != "text" {
		t.Fatalf("unexpected tools/call result: %s", lines[2])
	}

	if !strings.Contains(lines[3], "unknown tool") {
		t.Fatalf("expected unknown tool error as tool result: %s", lines[3])
	}
	if !strings.Contains(lines[4], "method not found") {
		t.Fatalf("expected method not found error: %s", lines[4])
	}
	if !strings.Contains(lines[5], "parse error") {
		t.Fatalf("expected parse error: %s", lines[5])
	}
}

func TestToolSchemasAreMCPValid(t *testing.T) {
	for _, tool := range Tools() {
		var document struct {
			Type       string           `json:"type"`
			Properties map[string]any   `json:"properties"`
			Required   *json.RawMessage `json:"required"`
		}
		if err := json.Unmarshal(tool.InputSchema, &document); err != nil {
			t.Fatalf("%s: invalid schema JSON: %v", tool.Name, err)
		}
		if document.Type != "object" {
			t.Errorf("%s: schema type = %q, want object", tool.Name, document.Type)
		}
		if document.Properties == nil {
			t.Errorf("%s: schema missing properties", tool.Name)
		}
		if document.Required != nil && string(*document.Required) == "null" {
			t.Errorf("%s: schema required is null; must be an array or omitted", tool.Name)
		}
		if document.Required != nil {
			var required []string
			if err := json.Unmarshal(*document.Required, &required); err != nil {
				t.Errorf("%s: schema required is not an array: %s", tool.Name, *document.Required)
			}
		}
	}
}

func TestClientEncodesOriginAndCSRF(t *testing.T) {
	var gotOrigin, gotCSRF string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/login", func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: strings.Repeat("a", 40), Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "s", Path: "/", HttpOnly: true})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/v1/admin/configs/shop/prod/api/publish", func(w http.ResponseWriter, r *http.Request) {
		gotCSRF = r.Header.Get(csrfHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"version":1}`))
	})
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	client, err := New(httpServer.URL, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callTool(t, client, "publish", map[string]any{
		"project": "shop", "environment": "prod", "service": "api",
	}); err != nil {
		t.Fatal(err)
	}
	if gotOrigin != httpServer.URL {
		t.Fatalf("Origin = %q, want %q", gotOrigin, httpServer.URL)
	}
	if gotCSRF != strings.Repeat("a", 40) {
		t.Fatalf("CSRF header = %q", gotCSRF)
	}
}
