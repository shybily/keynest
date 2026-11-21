package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kataras/iris/v12"
	"github.com/shybily/keynest/internal/config"
	"github.com/shybily/keynest/internal/secure"
	"github.com/shybily/keynest/internal/store"
)

const testSecret = "01234567890123456789012345678901"

type adminClient struct {
	t       *testing.T
	app     *iris.Application
	session *http.Cookie
	csrf    string
}

func newTestApp(t *testing.T) (*iris.Application, *store.Store) {
	t.Helper()
	repository, err := store.Open(":memory:", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	app := New(repository, "test-password", testSecret)
	if err := app.Build(); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { repository.Close() })
	return app, repository
}

func loginClient(t *testing.T, app *iris.Application) *adminClient {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login",
		strings.NewReader(`{"password":"test-password"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://example.com")
	recorder := httptest.NewRecorder()
	app.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	client := &adminClient{t: t, app: app}
	for _, cookie := range recorder.Result().Cookies() {
		switch cookie.Name {
		case sessionCookie:
			client.session = cookie
		case csrfCookie:
			client.csrf = cookie.Value
		}
	}
	if client.session == nil || client.csrf == "" {
		t.Fatalf("login did not set session and CSRF cookies: %v", recorder.Result().Cookies())
	}
	return client
}

func (c *adminClient) call(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var data io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		data = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, data)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if !isSafeMethod(method) {
		request.Header.Set("Origin", "http://example.com")
		request.Header.Set("X-CSRF-Token", c.csrf)
		request.AddCookie(&http.Cookie{Name: csrfCookie, Value: c.csrf})
	}
	request.AddCookie(c.session)
	recorder := httptest.NewRecorder()
	c.app.ServeHTTP(recorder, request)
	response := recorder.Result()
	result, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		c.t.Fatal(err)
	}
	return response, result
}

func publicCall(t *testing.T, app *iris.Application, method, path, token string) (*http.Response, []byte) {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	app.ServeHTTP(recorder, request)
	response := recorder.Result()
	payload, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, payload
}

func TestAdminPublishAndScopedClientRead(t *testing.T) {
	app, _ := newTestApp(t)

	response, payload := publicCall(t, app, http.MethodGet, "/", "")
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte("Keynest")) {
		t.Fatalf("embedded admin page status=%d body=%s", response.StatusCode, payload)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("admin page cache control = %q", response.Header.Get("Cache-Control"))
	}
	if !bytes.Contains(payload, []byte("/static/app.css?v=")) ||
		!bytes.Contains(payload, []byte("/static/app.js?v=")) {
		t.Fatalf("embedded admin page has no versioned static assets: %s", payload)
	}
	response, payload = publicCall(t, app, http.MethodGet, "/static/app.js", "")
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte("loadResources")) {
		t.Fatalf("embedded JavaScript status=%d body=%s", response.StatusCode, payload)
	}
	if response.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("unversioned static cache control = %q", response.Header.Get("Cache-Control"))
	}
	response, _ = publicCall(t, app, http.MethodGet, "/static/app.js?v=0.4.0", "")
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("versioned static response status=%d cache=%q",
			response.StatusCode, response.Header.Get("Cache-Control"))
	}
	response, _ = publicCall(t, app, http.MethodGet, "/api/v1/admin/configs", "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated admin request status = %d", response.StatusCode)
	}

	client := loginClient(t, app)
	address := "/api/v1/admin/configs/project/prod/api"
	body := map[string]any{
		"schema": []map[string]any{
			{"path": "http.port", "label": "HTTP 端口", "type": "integer", "environment": "APP_PORT"},
			{"path": "database.password", "label": "数据库密码", "type": "secret", "sensitive": true, "environment": "APP_DB_PASSWORD"},
		},
		"values": map[string]any{
			"http":     map[string]any{"port": 8080},
			"database": map[string]any{"password": "integration-secret"},
		},
	}
	response, payload = client.call(http.MethodPut, address, body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save draft status = %d, body = %s", response.StatusCode, payload)
	}
	response, payload = client.call(http.MethodPost, address+"/publish", map[string]any{})
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(`"version":1`)) {
		t.Fatalf("publish status = %d, body = %s", response.StatusCode, payload)
	}
	response, _ = publicCall(t, app, http.MethodGet, "/api/v1/configs/project/prod/api", "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized config read status = %d", response.StatusCode)
	}

	response, payload = client.call(http.MethodPost, "/api/v1/admin/keys", map[string]string{
		"name": "api runtime", "project": "project", "environment": "prod", "service": "api",
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create access key status = %d, body = %s", response.StatusCode, payload)
	}
	var created struct {
		Token string `json:"token"`
		Key   struct {
			ID string `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal(payload, &created); err != nil || created.Token == "" {
		t.Fatalf("invalid create key response: %s (%v)", payload, err)
	}
	response, privatePEM := client.call(http.MethodGet, "/api/v1/admin/keys/"+created.Key.ID+"/private-key", nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(privatePEM, []byte("PRIVATE KEY")) {
		t.Fatalf("download private key status=%d body=%s", response.StatusCode, privatePEM)
	}

	response, payload = client.call(http.MethodGet, address, nil)
	if response.StatusCode != http.StatusOK || bytes.Contains(payload, []byte("integration-secret")) {
		t.Fatalf("admin draft did not redact secret: status=%d body=%s", response.StatusCode, payload)
	}
	if !bytes.Contains(payload, []byte(keepSecret)) {
		t.Fatalf("admin draft did not return the secret placeholder: %s", payload)
	}

	decryptRead := func() map[string]any {
		t.Helper()
		response, payload := publicCall(t, app, http.MethodGet, "/api/v1/configs/project/prod/api", created.Token)
		if response.StatusCode != http.StatusOK || bytes.Contains(payload, []byte("integration-secret")) {
			t.Fatalf("authorized config read status=%d body=%s", response.StatusCode, payload)
		}
		var envelope secure.Envelope
		if err := json.Unmarshal(payload, &envelope); err != nil {
			t.Fatal(err)
		}
		plain, err := secure.Decrypt(privatePEM, envelope, config.Address{
			Project: "project", Environment: "prod", Service: "api",
		})
		if err != nil {
			t.Fatalf("decrypt config response: %v", err)
		}
		var document struct {
			Values map[string]any `json:"values"`
		}
		if err := json.Unmarshal(plain, &document); err != nil {
			t.Fatalf("decode plaintext: %v (%s)", err, plain)
		}
		return document.Values
	}
	values := decryptRead()
	if values["database"].(map[string]any)["password"] != "integration-secret" {
		t.Fatalf("unexpected decrypted secret: %#v", values)
	}
	response, payload = publicCall(t, app, http.MethodGet, "/api/v1/configs/project/prod/other", created.Token)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope config read status=%d body=%s", response.StatusCode, payload)
	}
	response, payload = publicCall(t, app, http.MethodGet, "/api/v1/configs/project/prod/api/render/env", created.Token)
	if response.StatusCode != http.StatusOK || bytes.Contains(payload, []byte("integration-secret")) {
		t.Fatalf("authorized environment rendering status=%d body=%s", response.StatusCode, payload)
	}
	var envelope secure.Envelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	plain, err := secure.Decrypt(privatePEM, envelope, config.Address{
		Project: "project", Environment: "prod", Service: "api",
	})
	if err != nil || !strings.Contains(string(plain), "APP_DB_PASSWORD=integration-secret") {
		t.Fatalf("decrypt rendered config: body=%s error=%v", plain, err)
	}

	body["values"].(map[string]any)["http"].(map[string]any)["port"] = 9090
	body["values"].(map[string]any)["database"].(map[string]any)["password"] = keepSecret
	body["preserveSecrets"] = []string{"database.password"}
	response, payload = client.call(http.MethodPut, address, body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save preserved draft status=%d body=%s", response.StatusCode, payload)
	}
	response, payload = client.call(http.MethodPost, address+"/publish", map[string]any{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("publish preserved draft status=%d body=%s", response.StatusCode, payload)
	}
	values = decryptRead()
	if values["http"].(map[string]any)["port"] != float64(9090) ||
		values["database"].(map[string]any)["password"] != "integration-secret" {
		t.Fatalf("preserved secret changed: %#v", values)
	}

	delete(body, "preserveSecrets")
	response, payload = client.call(http.MethodPut, address, body)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("placeholder without preserveSecrets status=%d body=%s", response.StatusCode, payload)
	}

	delete(body["values"].(map[string]any)["database"].(map[string]any), "password")
	body["clearSecrets"] = []string{"database.password"}
	response, payload = client.call(http.MethodPut, address, body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("clear secret draft status=%d body=%s", response.StatusCode, payload)
	}
	delete(body, "clearSecrets")
	response, payload = client.call(http.MethodGet, address, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("cleared secret draft status=%d body=%s", response.StatusCode, payload)
	}
	var clearedDraft struct {
		SecretSet []string `json:"secretSet"`
	}
	if err := json.Unmarshal(payload, &clearedDraft); err != nil {
		t.Fatalf("decode cleared draft: %v", err)
	}
	for _, path := range clearedDraft.SecretSet {
		if path == "database.password" {
			t.Fatalf("cleared secret still marked as set: %s", payload)
		}
	}
	response, payload = client.call(http.MethodPost, address+"/publish", map[string]any{})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("publish cleared secret status=%d body=%s", response.StatusCode, payload)
	}
	values = decryptRead()
	if password, ok := values["database"].(map[string]any)["password"]; ok && password != "" {
		t.Fatalf("cleared secret still has a value: %#v", values)
	}

	response, payload = client.call(http.MethodPost, address+"/import", map[string]string{
		"format": "json", "content": `{"http":{"port":7070}}`,
	})
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(`"fields":1`)) {
		t.Fatalf("import JSON draft status=%d body=%s", response.StatusCode, payload)
	}
	values = decryptRead()
	if values["http"].(map[string]any)["port"] != float64(9090) {
		t.Fatalf("import unexpectedly published config: %#v", values)
	}
}

func TestEnvironmentAndServiceLifecycle(t *testing.T) {
	app, _ := newTestApp(t)
	client := loginClient(t, app)

	response, payload := client.call(http.MethodPost, "/api/v1/admin/projects",
		map[string]string{"id": "demo", "name": "Demo"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create project status=%d body=%s", response.StatusCode, payload)
	}
	response, payload = client.call(http.MethodPost, "/api/v1/admin/projects/demo/environments",
		map[string]string{"name": "prod"})
	if response.StatusCode != http.StatusCreated || bytes.Contains(payload, []byte(`"token"`)) {
		t.Fatalf("create environment status=%d body=%s", response.StatusCode, payload)
	}
	response, payload = client.call(http.MethodPost,
		"/api/v1/admin/projects/demo/environments/prod/services",
		map[string]string{"name": "api"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create service status=%d body=%s", response.StatusCode, payload)
	}
	var created struct {
		Token string          `json:"token"`
		Key   store.AccessKey `json:"key"`
	}
	if err := json.Unmarshal(payload, &created); err != nil || created.Token == "" || created.Key.ID == "" {
		t.Fatalf("service creation response=%s err=%v", payload, err)
	}

	response, payload = client.call(http.MethodGet, "/api/v1/admin/resources", nil)
	if response.StatusCode != http.StatusOK ||
		!bytes.Contains(payload, []byte(`"environments"`)) ||
		!bytes.Contains(payload, []byte(created.Key.ID)) {
		t.Fatalf("resource tree status=%d body=%s", response.StatusCode, payload)
	}
	response, _ = client.call(http.MethodDelete,
		"/api/v1/admin/projects/demo/environments/prod/services/api/key", nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete service key status=%d", response.StatusCode)
	}
	response, payload = client.call(http.MethodGet, "/api/v1/admin/resources", nil)
	if response.StatusCode != http.StatusOK || bytes.Contains(payload, []byte(created.Key.ID)) {
		t.Fatalf("deleted key remains in resource tree: status=%d body=%s", response.StatusCode, payload)
	}
	response, _ = client.call(http.MethodDelete,
		"/api/v1/admin/projects/demo/environments/prod/services/api", nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete service status=%d", response.StatusCode)
	}
	response, payload = client.call(http.MethodGet, "/api/v1/admin/resources", nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(payload, []byte(`"environments"`)) ||
		bytes.Contains(payload, []byte(`"services":[{"project"`)) {
		t.Fatalf("environment not retained after service delete: status=%d body=%s", response.StatusCode, payload)
	}
	response, _ = client.call(http.MethodDelete, "/api/v1/admin/projects/demo/environments/prod", nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete environment status=%d", response.StatusCode)
	}
}

func TestLoginRateLimitAndCSRF(t *testing.T) {
	app, _ := newTestApp(t)
	login := func(password, origin string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/login",
			strings.NewReader(`{"password":"`+password+`"}`))
		request.Header.Set("Content-Type", "application/json")
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		recorder := httptest.NewRecorder()
		app.ServeHTTP(recorder, request)
		return recorder
	}

	recorder := login("test-password", "https://evil.example")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status=%d", recorder.Code)
	}
	for attempt := 1; attempt <= 4; attempt++ {
		recorder = login("wrong-password", "http://example.com")
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("login attempt %d status=%d body=%s", attempt, recorder.Code, recorder.Body.String())
		}
	}
	recorder = login("wrong-password", "http://example.com")
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") == "" {
		t.Fatalf("lockout status=%d retry=%q body=%s", recorder.Code,
			recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
	recorder = login("test-password", "http://example.com")
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("correct password bypassed lockout: status=%d", recorder.Code)
	}

	otherApp, _ := newTestApp(t)
	client := loginClient(t, otherApp)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects",
		strings.NewReader(`{"id":"demo","name":"Demo"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(client.session)
	recorder = httptest.NewRecorder()
	otherApp.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF token status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/projects",
		strings.NewReader(`{"id":"demo","name":"Demo"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("X-CSRF-Token", client.csrf)
	request.AddCookie(client.session)
	request.AddCookie(&http.Cookie{Name: csrfCookie, Value: client.csrf})
	recorder = httptest.NewRecorder()
	otherApp.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cross-origin admin write status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	response, payload := client.call(http.MethodPost, "/api/v1/admin/projects",
		map[string]string{"id": "demo", "name": "Demo"})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("CSRF-protected write status=%d body=%s", response.StatusCode, payload)
	}
}

func TestSessionTokenExpiryAndTampering(t *testing.T) {
	s := &Server{authSecret: []byte(testSecret)}
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	token := s.sessionToken(now.Add(-29*time.Minute).Unix(), now.Add(-29*time.Minute).Unix(), randomToken())
	state, ok := s.readSession(&http.Cookie{Value: token}, now)
	if !ok || !s.sessionValid(state, now) {
		t.Fatal("fresh session should be valid")
	}
	token = s.sessionToken(now.Add(-31*time.Minute).Unix(), now.Add(-31*time.Minute).Unix(), randomToken())
	state, ok = s.readSession(&http.Cookie{Value: token}, now)
	if !ok || s.sessionValid(state, now) {
		t.Fatal("idle session should be invalid")
	}
	token = s.sessionToken(now.Add(-13*time.Hour).Unix(), now.Unix(), randomToken())
	state, ok = s.readSession(&http.Cookie{Value: token}, now)
	if !ok || s.sessionValid(state, now) {
		t.Fatal("session past the absolute limit should be invalid")
	}
	token = s.sessionToken(now.Unix(), now.Unix(), randomToken())
	if _, ok := s.readSession(&http.Cookie{Value: token + "x"}, now); ok {
		t.Fatal("tampered session token was accepted")
	}
	if _, ok := s.readSession(&http.Cookie{Value: "1700000000.deadbeef"}, now); ok {
		t.Fatal("legacy session token was accepted")
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	s := &Server{trustedProxies: mustProxies(t, "10.0.0.0/8")}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.2.3:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 10.1.1.1")
	if got := s.clientIPFromRequest(request); got != "203.0.113.9" {
		t.Fatalf("clientIP() = %q, want 203.0.113.9", got)
	}

	untrusted := &Server{}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "198.51.100.7:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := untrusted.clientIPFromRequest(request); got != "198.51.100.7" {
		t.Fatalf("untrusted clientIP() = %q, want 198.51.100.7", got)
	}
}

func mustProxies(t *testing.T, values ...string) []*net.IPNet {
	t.Helper()
	proxies, err := parseTrustedProxies(values)
	if err != nil {
		t.Fatal(err)
	}
	return proxies
}
