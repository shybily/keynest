package store

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shybily/keynest/internal/config"
)

func TestDraftPublishHistoryAndEncryption(t *testing.T) {
	repository, err := Open(":memory:", "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	address := config.Address{Project: "sample", Environment: "test", Service: "api"}
	draft := config.Draft{
		Schema: []config.Field{
			{Path: "server.port", Label: "Port", Type: "integer"},
			{Path: "database.password", Label: "Password", Type: "secret", Sensitive: true},
		},
		Values: map[string]any{
			"server":   map[string]any{"port": float64(8080)},
			"database": map[string]any{"password": "plain-secret-value"},
		},
	}
	if err := repository.SaveDraft(address, draft); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := repository.db.QueryRow(`SELECT draft_values FROM configs`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("plain-secret-value")) {
		t.Fatal("configuration values were stored without encryption")
	}
	if version, err := repository.Publish(address, "test"); err != nil || version != 1 {
		t.Fatalf("Publish() = (%d, %v), want (1, nil)", version, err)
	}
	published, err := repository.GetPublished(address)
	if err != nil {
		t.Fatal(err)
	}
	if published.Version != 1 || published.Values["database"].(map[string]any)["password"] != "plain-secret-value" {
		t.Fatalf("unexpected published document: %#v", published)
	}

	draft.Values["server"].(map[string]any)["port"] = float64(9090)
	if err := repository.SaveDraft(address, draft); err != nil {
		t.Fatal(err)
	}
	published, err = repository.GetPublished(address)
	if err != nil {
		t.Fatal(err)
	}
	if published.Values["server"].(map[string]any)["port"] != float64(8080) {
		t.Fatal("saving a draft changed the published configuration")
	}
	history, err := repository.History(address)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].Version != 1 {
		t.Fatalf("unexpected history: %#v", history)
	}
}

func TestGetPublishedRequiresPublishedVersion(t *testing.T) {
	repository, err := Open(":memory:", "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	address := config.Address{Project: "sample", Environment: "test", Service: "api"}
	_, err = repository.GetPublished(address)
	if err == nil || err != sql.ErrNoRows {
		t.Fatalf("GetPublished() error = %v, want sql.ErrNoRows", err)
	}
}

func TestResourceHierarchyAndServiceKey(t *testing.T) {
	repository, err := Open(":memory:", "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	if err := repository.CreateProject("demo", "Demo"); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateEnvironment("demo", "prod"); err != nil {
		t.Fatal(err)
	}
	key := AccessKey{ID: "env-key", Name: "api/prod", Project: "demo", Environment: "prod", Service: "api", CreatedAt: now()}
	if err := repository.CreateServiceWithKey("demo", "prod", "api", key,
		"token-hash", "public-key", "private-key"); err != nil {
		t.Fatal(err)
	}
	resources, err := repository.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || len(resources[0].Environments) != 1 ||
		len(resources[0].Environments[0].Services) != 1 ||
		resources[0].Environments[0].Services[0].KeyID != "env-key" {
		t.Fatalf("unexpected resource tree: %#v", resources)
	}
	if err := repository.DeleteServiceKey("demo", "prod", "api"); err != nil {
		t.Fatal(err)
	}
	if _, authorized, err := repository.AuthenticateKey("token-hash", "demo", "prod", "api"); err != nil || authorized {
		t.Fatalf("deleted service key remains authorized: authorized=%v err=%v", authorized, err)
	}
	if err := repository.DeleteEnvironment("demo", "prod", "test"); err != nil {
		t.Fatal(err)
	}
	resources, err = repository.ListResources()
	if err != nil || len(resources[0].Environments) != 0 {
		t.Fatalf("deleted environment remains in resource tree: %#v, %v", resources, err)
	}
}

func TestSameServiceNameAcrossEnvironments(t *testing.T) {
	repository, err := Open(":memory:", "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if err := repository.CreateProject("demo", "Demo"); err != nil {
		t.Fatal(err)
	}
	for _, environment := range []string{"prod", "staging"} {
		if err := repository.CreateEnvironment("demo", environment); err != nil {
			t.Fatal(err)
		}
		key := AccessKey{
			ID: environment + "-key", Name: "api/" + environment, Project: "demo",
			Environment: environment, Service: "api", CreatedAt: now(),
		}
		if err := repository.CreateServiceWithKey("demo", environment, "api", key,
			environment+"-hash", "public-key", "private-key"); err != nil {
			t.Fatal(err)
		}
	}
	resources, err := repository.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || len(resources[0].Environments) != 2 {
		t.Fatalf("unexpected resource tree: %#v", resources)
	}
	if err := repository.DeleteService("demo", "staging", "api", "test"); err != nil {
		t.Fatal(err)
	}
	resources, err = repository.ListResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(resources[0].Environments) != 2 ||
		len(resources[0].Environments[0].Services) != 1 ||
		len(resources[0].Environments[1].Services) != 0 {
		t.Fatalf("deleting staging service affected prod: %#v", resources)
	}
}

func TestOpenRejectsLegacyResourceSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE services (
	project TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (project, name));
	CREATE TABLE environments (
	project TEXT NOT NULL, service TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL,
	PRIMARY KEY (project, service, name));`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path, "01234567890123456789012345678901"); err == nil ||
		!strings.Contains(err.Error(), "legacy project-service-environment schema") {
		t.Fatalf("Open() error = %v, want legacy schema rejection", err)
	}
}

func TestAccessKeyStoresOnlyEncryptedPrivateKeyAndEnforcesScope(t *testing.T) {
	repository, err := Open(":memory:", "01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()

	key := AccessKey{
		ID: "key-id", Name: "runtime", Project: "sample", Environment: "prod",
		Service: "api", CreatedAt: now(),
	}
	privatePEM := "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"
	if err := repository.CreateKey(key, "token-hash", "public-material", privatePEM); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := repository.db.QueryRow(`SELECT private_key_cipher FROM access_keys WHERE id=?`, key.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("private-material")) {
		t.Fatal("private key was stored without encryption")
	}
	restored, err := repository.PrivateKey(key.ID)
	if err != nil || restored != privatePEM {
		t.Fatalf("PrivateKey() = (%q, %v)", restored, err)
	}
	credential, authorized, err := repository.AuthenticateKey("token-hash", "sample", "prod", "api")
	if err != nil || !authorized || credential.ID != key.ID || string(credential.PublicKey) != "public-material" {
		t.Fatalf("AuthenticateKey() = (%#v, %v, %v)", credential, authorized, err)
	}
	_, authorized, err = repository.AuthenticateKey("token-hash", "sample", "dev", "api")
	if err != nil || authorized {
		t.Fatalf("out-of-scope AuthenticateKey() = (%v, %v)", authorized, err)
	}
}
