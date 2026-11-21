package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shybily/keynest/internal/config"
	_ "modernc.org/sqlite"
)

type Store struct {
	db            *sql.DB
	encryptionKey [32]byte
}

type Summary struct {
	Address config.Address `json:"address"`
	Version int            `json:"version"`
	Updated string         `json:"updatedAt"`
}

type AccessKey struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Service     string `json:"service"`
	CreatedAt   string `json:"createdAt"`
}

type ReadCredential struct {
	ID        string
	PublicKey []byte
}

const environmentConfigKey = "__environment__"

type Project struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

type Environment struct {
	Project   string `json:"project"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

type Service struct {
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Name        string `json:"name"`
	CreatedAt   string `json:"createdAt"`
	KeyID       string `json:"keyId,omitempty"`
}

type ResourceTree struct {
	Projects []ProjectResource `json:"projects"`
}

type ProjectResource struct {
	Project
	Environments []EnvironmentResource `json:"environments"`
}

type EnvironmentResource struct {
	Environment
	Services []Service `json:"services"`
}

func Open(path, encryptionSecret string) (*Store, error) {
	if len(encryptionSecret) < 32 {
		return nil, fmt.Errorf("configuration encryption secret must be at least 32 bytes")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure SQLite: %w", err)
	}
	s := &Store{db: db, encryptionKey: sha256.Sum256([]byte(encryptionSecret))}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	if err := s.rejectLegacySchema(); err != nil {
		return err
	}
	const schema = `
CREATE TABLE IF NOT EXISTS configs (
  project TEXT NOT NULL,
  environment TEXT NOT NULL,
  service TEXT NOT NULL,
  module TEXT NOT NULL,
  draft_schema TEXT NOT NULL,
  draft_values BLOB NOT NULL,
  published_schema TEXT NOT NULL DEFAULT '[]',
  published_values BLOB NOT NULL DEFAULT '{}',
  version INTEGER NOT NULL DEFAULT 0,
  published_at TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY (project, environment, service, module)
);
CREATE TABLE IF NOT EXISTS config_history (
  project TEXT NOT NULL,
  environment TEXT NOT NULL,
  service TEXT NOT NULL,
  module TEXT NOT NULL,
  version INTEGER NOT NULL,
  schema_json TEXT NOT NULL,
  values_cipher BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (project, environment, service, module, version)
);
CREATE TABLE IF NOT EXISTS access_keys (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  project TEXT NOT NULL,
  environment TEXT NOT NULL,
  service TEXT NOT NULL,
  environment_id TEXT NOT NULL DEFAULT '',
  key_hash TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  private_key_cipher BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  project TEXT NOT NULL DEFAULT '',
  environment TEXT NOT NULL DEFAULT '',
  service TEXT NOT NULL DEFAULT '',
  module TEXT NOT NULL DEFAULT '',
  details TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS environments (
  project TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (project, name),
  FOREIGN KEY (project) REFERENCES projects(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS services (
  project TEXT NOT NULL,
  environment TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (project, environment, name),
  FOREIGN KEY (project, environment) REFERENCES environments(project, name) ON DELETE CASCADE
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("initialize SQLite schema: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA user_version=2`); err != nil {
		return fmt.Errorf("set SQLite schema version: %w", err)
	}
	return nil
}

func (s *Store) rejectLegacySchema() error {
	servicesExist, err := s.tableExists("services")
	if err != nil {
		return err
	}
	if servicesExist {
		columns, err := s.tableColumns("services")
		if err != nil {
			return err
		}
		if !columns["environment"] {
			return fmt.Errorf("database uses the legacy project-service-environment schema; remove the database file and restart Keynest")
		}
	}
	environmentsExist, err := s.tableExists("environments")
	if err != nil {
		return err
	}
	if environmentsExist {
		columns, err := s.tableColumns("environments")
		if err != nil {
			return err
		}
		if columns["service"] {
			return fmt.Errorf("database uses the legacy project-service-environment schema; remove the database file and restart Keynest")
		}
	}
	return nil
}

func (s *Store) tableExists(name string) (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) tableColumns(table string) (map[string]bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[name] = true
	}
	return columns, rows.Err()
}

func (s *Store) ListResources() ([]ProjectResource, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at FROM projects ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var projects []Project
	for rows.Next() {
		var project Project
		if err := rows.Scan(&project.ID, &project.Name, &project.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		projects = append(projects, project)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	var result []ProjectResource
	for _, project := range projects {
		resource := ProjectResource{Project: project}
		environmentRows, err := s.db.Query(`SELECT project, name, created_at FROM environments
	WHERE project=? ORDER BY name`, project.ID)
		if err != nil {
			return nil, err
		}
		var environments []Environment
		for environmentRows.Next() {
			var environment Environment
			if err := environmentRows.Scan(&environment.Project, &environment.Name, &environment.CreatedAt); err != nil {
				environmentRows.Close()
				return nil, err
			}
			environments = append(environments, environment)
		}
		if err := environmentRows.Err(); err != nil {
			environmentRows.Close()
			return nil, err
		}
		if err := environmentRows.Close(); err != nil {
			return nil, err
		}

		for _, environment := range environments {
			environmentResource := EnvironmentResource{Environment: environment}
			serviceRows, err := s.db.Query(`SELECT s.project, s.environment, s.name, s.created_at,
	COALESCE((SELECT id FROM access_keys k
	  WHERE k.project=s.project AND k.environment=s.environment AND k.service=s.name LIMIT 1), '')
	FROM services s WHERE s.project=? AND s.environment=? ORDER BY s.name`,
				project.ID, environment.Name)
			if err != nil {
				return nil, err
			}
			for serviceRows.Next() {
				var service Service
				if err := serviceRows.Scan(&service.Project, &service.Environment, &service.Name,
					&service.CreatedAt, &service.KeyID); err != nil {
					serviceRows.Close()
					return nil, err
				}
				environmentResource.Services = append(environmentResource.Services, service)
			}
			if err := serviceRows.Err(); err != nil {
				serviceRows.Close()
				return nil, err
			}
			if err := serviceRows.Close(); err != nil {
				return nil, err
			}
			resource.Environments = append(resource.Environments, environmentResource)
		}
		result = append(result, resource)
	}
	return result, nil
}

func (s *Store) CreateProject(id, name string) error {
	if name == "" {
		name = id
	}
	timestamp := now()
	_, err := s.db.Exec(`INSERT INTO projects(id, name, created_at, updated_at) VALUES(?, ?, ?, ?)`,
		id, name, timestamp, timestamp)
	return err
}

func (s *Store) CreateEnvironment(project, name string) error {
	_, err := s.db.Exec(`INSERT INTO environments(project, name, created_at) VALUES(?, ?, ?)`,
		project, name, now())
	return err
}

func (s *Store) CreateService(project, environment, name string) error {
	_, err := s.db.Exec(`INSERT INTO services(project, environment, name, created_at) VALUES(?, ?, ?, ?)`,
		project, environment, name, now())
	return err
}

func (s *Store) ensureResourceAddress(address config.Address) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	timestamp := now()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO projects(id, name, created_at, updated_at) VALUES(?, ?, ?, ?)`,
		address.Project, address.Project, timestamp, timestamp); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO environments(project, name, created_at) VALUES(?, ?, ?)`,
		address.Project, address.Environment, timestamp); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO services(project, environment, name, created_at) VALUES(?, ?, ?, ?)`,
		address.Project, address.Environment, address.Service, timestamp); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateServiceWithKey(project, environment, name string, key AccessKey, hash, publicKey, privateKey string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	timestamp := now()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO projects(id, name, created_at, updated_at) VALUES(?, ?, ?, ?)`,
		project, project, timestamp, timestamp); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO environments(project, name, created_at) VALUES(?, ?, ?)`,
		project, environment, timestamp); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO services(project, environment, name, created_at) VALUES(?, ?, ?, ?)`,
		project, environment, name, timestamp); err != nil {
		return err
	}
	privateCipher, err := s.encryptJSON(privateKey)
	if err != nil {
		return err
	}
	environmentID := project + string(rune(31)) + environment
	if _, err := tx.Exec(`INSERT INTO access_keys
	(id, name, project, environment, service, environment_id, key_hash, public_key, private_key_cipher, created_at)
	VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.Name, project, environment, name, environmentID, hash, publicKey, privateCipher, timestamp); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReplaceServiceKey(project, environment, service string, key AccessKey, hash, publicKey, privateKey string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM access_keys WHERE project=? AND environment=? AND service=?`,
		project, environment, service); err != nil {
		return err
	}
	privateCipher, err := s.encryptJSON(privateKey)
	if err != nil {
		return err
	}
	environmentID := project + string(rune(31)) + environment
	if _, err := tx.Exec(`INSERT INTO access_keys
	(id, name, project, environment, service, environment_id, key_hash, public_key, private_key_cipher, created_at)
	VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.Name, project, environment, service, environmentID, hash, publicKey, privateCipher, key.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteServiceKey(project, environment, service string) error {
	result, err := s.db.Exec(`DELETE FROM access_keys WHERE project=? AND environment=? AND service=?`,
		project, environment, service)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteProject(project, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM config_history WHERE project=?`, []any{project}},
		{`DELETE FROM configs WHERE project=?`, []any{project}},
		{`DELETE FROM access_keys WHERE project=?`, []any{project}},
		{`DELETE FROM services WHERE project=?`, []any{project}},
		{`DELETE FROM environments WHERE project=?`, []any{project}},
		{`DELETE FROM projects WHERE id=?`, []any{project}},
	} {
		if _, err := tx.Exec(statement.query, statement.args...); err != nil {
			return err
		}
	}
	if err := audit(tx, actor, "delete-project", config.Address{Project: project}, project); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteService(project, environment, service, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{
		`DELETE FROM config_history WHERE project=? AND environment=? AND service=?`,
		`DELETE FROM configs WHERE project=? AND environment=? AND service=?`,
		`DELETE FROM access_keys WHERE project=? AND environment=? AND service=?`,
		`DELETE FROM services WHERE project=? AND environment=? AND name=?`,
	} {
		if _, err := tx.Exec(query, project, environment, service); err != nil {
			return err
		}
	}
	if err := audit(tx, actor, "delete-service",
		config.Address{Project: project, Environment: environment, Service: service}, service); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteEnvironment(project, environment, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, query := range []string{
		`DELETE FROM config_history WHERE project=? AND environment=?`,
		`DELETE FROM configs WHERE project=? AND environment=?`,
		`DELETE FROM access_keys WHERE project=? AND environment=?`,
		`DELETE FROM services WHERE project=? AND environment=?`,
		`DELETE FROM environments WHERE project=? AND name=?`,
	} {
		if _, err := tx.Exec(query, project, environment); err != nil {
			return err
		}
	}
	if err := audit(tx, actor, "delete-environment",
		config.Address{Project: project, Environment: environment}, environment); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteEnvironmentConfig(address config.Address, actor string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM config_history WHERE project=? AND environment=? AND service=?`,
		address.Project, address.Environment, address.Service); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM configs WHERE project=? AND environment=? AND service=?`,
		address.Project, address.Environment, address.Service); err != nil {
		return err
	}
	if err := audit(tx, actor, "delete-environment-config", address, ""); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SaveDraft(address config.Address, draft config.Draft) error {
	if err := s.ensureResourceAddress(address); err != nil {
		return err
	}
	schemaJSON, err := json.Marshal(draft.Schema)
	if err != nil {
		return err
	}
	valuesCipher, err := s.encryptJSON(draft.Values)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO configs(project, environment, service, module, draft_schema, draft_values, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(project, environment, service, module) DO UPDATE SET
  draft_schema=excluded.draft_schema, draft_values=excluded.draft_values, updated_at=excluded.updated_at`,
		address.Project, address.Environment, address.Service, environmentConfigKey,
		string(schemaJSON), valuesCipher, now())
	return err
}

func (s *Store) GetDraft(address config.Address) (config.Draft, int, string, error) {
	var schemaJSON string
	var valuesCipher []byte
	var version int
	var updated string
	err := s.db.QueryRow(`SELECT draft_schema, draft_values, version, updated_at FROM configs
WHERE project=? AND environment=? AND service=? AND module=?`,
		address.Project, address.Environment, address.Service, environmentConfigKey).
		Scan(&schemaJSON, &valuesCipher, &version, &updated)
	if err != nil {
		return config.Draft{}, 0, "", err
	}
	var draft config.Draft
	if err := json.Unmarshal([]byte(schemaJSON), &draft.Schema); err != nil {
		return draft, 0, "", err
	}
	if err := s.decryptJSON(valuesCipher, &draft.Values); err != nil {
		return draft, 0, "", err
	}
	return draft, version, updated, nil
}

func (s *Store) GetPublished(address config.Address) (config.Document, error) {
	var schemaJSON string
	var valuesCipher []byte
	var version int
	var updated string
	err := s.db.QueryRow(`SELECT published_schema, published_values, version, published_at FROM configs
WHERE project=? AND environment=? AND service=? AND module=?`,
		address.Project, address.Environment, address.Service, environmentConfigKey).
		Scan(&schemaJSON, &valuesCipher, &version, &updated)
	if err != nil {
		return config.Document{}, err
	}
	if version == 0 {
		return config.Document{}, sql.ErrNoRows
	}
	var document config.Document
	document.Address = address
	document.Version = version
	document.Updated = updated
	if err := json.Unmarshal([]byte(schemaJSON), &document.Schema); err != nil {
		return document, err
	}
	if err := s.decryptJSON(valuesCipher, &document.Values); err != nil {
		return document, err
	}
	return document, nil
}

func (s *Store) Publish(address config.Address, actor string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var schemaJSON string
	var valuesCipher []byte
	var version int
	err = tx.QueryRow(`SELECT draft_schema, draft_values, version FROM configs
WHERE project=? AND environment=? AND service=? AND module=?`,
		address.Project, address.Environment, address.Service, environmentConfigKey).
		Scan(&schemaJSON, &valuesCipher, &version)
	if err != nil {
		return 0, err
	}
	nextVersion := version + 1
	created := now()
	if _, err := tx.Exec(`INSERT INTO config_history
(project, environment, service, module, version, schema_json, values_cipher, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		address.Project, address.Environment, address.Service, environmentConfigKey,
		nextVersion, schemaJSON, valuesCipher, created); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE configs SET published_schema=?, published_values=?, version=?, published_at=?, updated_at=?
WHERE project=? AND environment=? AND service=? AND module=?`,
		schemaJSON, valuesCipher, nextVersion, created, created,
		address.Project, address.Environment, address.Service, environmentConfigKey); err != nil {
		return 0, err
	}
	if err := audit(tx, actor, "publish", address, fmt.Sprintf("version=%d", nextVersion)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return nextVersion, nil
}

func (s *Store) List() ([]Summary, error) {
	rows, err := s.db.Query(`SELECT project, environment, service, version, updated_at
FROM configs WHERE module=? ORDER BY project, environment, service`, environmentConfigKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Summary
	for rows.Next() {
		var item Summary
		if err := rows.Scan(&item.Address.Project, &item.Address.Environment, &item.Address.Service,
			&item.Version, &item.Updated); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) History(address config.Address) ([]config.History, error) {
	rows, err := s.db.Query(`SELECT version, schema_json, values_cipher, created_at FROM config_history
WHERE project=? AND environment=? AND service=? AND module=? ORDER BY version DESC`,
		address.Project, address.Environment, address.Service, environmentConfigKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []config.History
	for rows.Next() {
		var item config.History
		var schemaJSON string
		var valuesCipher []byte
		if err := rows.Scan(&item.Version, &schemaJSON, &valuesCipher, &item.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(schemaJSON), &item.Schema); err != nil {
			return nil, err
		}
		if err := s.decryptJSON(valuesCipher, &item.Values); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) Restore(address config.Address, version int, actor string) error {
	var schemaJSON string
	var valuesCipher []byte
	err := s.db.QueryRow(`SELECT schema_json, values_cipher FROM config_history
WHERE project=? AND environment=? AND service=? AND module=? AND version=?`,
		address.Project, address.Environment, address.Service, environmentConfigKey, version).
		Scan(&schemaJSON, &valuesCipher)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE configs SET draft_schema=?, draft_values=?, updated_at=?
WHERE project=? AND environment=? AND service=? AND module=?`,
		schemaJSON, valuesCipher, now(), address.Project, address.Environment, address.Service, environmentConfigKey); err != nil {
		return err
	}
	if err := audit(tx, actor, "restore-draft", address, fmt.Sprintf("source_version=%d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateKey(key AccessKey, hash string, publicKey, privateKey string) error {
	privateCipher, err := s.encryptJSON(privateKey)
	if err != nil {
		return err
	}
	environmentID := key.Project + string(rune(31)) + key.Environment
	_, err = s.db.Exec(`INSERT INTO access_keys
(id, name, project, environment, service, environment_id, key_hash, public_key, private_key_cipher, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, key.ID, key.Name, key.Project, key.Environment,
		key.Service, environmentID, hash, publicKey, privateCipher, key.CreatedAt)
	return err
}

func (s *Store) PrivateKey(id string) (string, error) {
	var encrypted []byte
	if err := s.db.QueryRow(`SELECT private_key_cipher FROM access_keys WHERE id=?`, id).Scan(&encrypted); err != nil {
		return "", err
	}
	var privateKey string
	if err := s.decryptJSON(encrypted, &privateKey); err != nil {
		return "", err
	}
	return privateKey, nil
}

func (s *Store) ListKeys() ([]AccessKey, error) {
	rows, err := s.db.Query(`SELECT id, name, project, environment, service, created_at
FROM access_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []AccessKey
	for rows.Next() {
		var key AccessKey
		if err := rows.Scan(&key.ID, &key.Name, &key.Project, &key.Environment, &key.Service, &key.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	return result, rows.Err()
}

func (s *Store) DeleteKey(id, actor string) error {
	result, err := s.db.Exec(`DELETE FROM access_keys WHERE id=?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	_, err = s.db.Exec(`INSERT INTO audit_log(actor, action, details, created_at) VALUES(?, 'revoke-key', ?, ?)`,
		actor, id, now())
	return err
}

func (s *Store) AuthenticateKey(hash, project, environment, service string) (ReadCredential, bool, error) {
	var credential ReadCredential
	err := s.db.QueryRow(`SELECT id, public_key FROM access_keys
WHERE key_hash=? AND project=? AND environment=? AND service=?`,
		hash, project, environment, service).Scan(&credential.ID, &credential.PublicKey)
	if err == sql.ErrNoRows {
		return ReadCredential{}, false, nil
	}
	if err != nil {
		return ReadCredential{}, false, err
	}
	return credential, true, nil
}

func (s *Store) Audit(actor, action string, address config.Address, details string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(actor, action, project, environment, service, module, details, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, actor, action, address.Project, address.Environment,
		address.Service, "", details, now())
	return err
}

func audit(tx *sql.Tx, actor, action string, address config.Address, details string) error {
	_, err := tx.Exec(`INSERT INTO audit_log(actor, action, project, environment, service, module, details, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, actor, action, address.Project, address.Environment,
		address.Service, "", details, now())
	return err
}

func (s *Store) encryptJSON(value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.encryptionKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return []byte(base64.RawStdEncoding.EncodeToString(ciphertext)), nil
}

func (s *Store) decryptJSON(ciphertext []byte, target any) error {
	decoded, err := base64.RawStdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.encryptionKey[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(decoded) < gcm.NonceSize() {
		return fmt.Errorf("encrypted value is truncated")
	}
	plain, err := gcm.Open(nil, decoded[:gcm.NonceSize()], decoded[gcm.NonceSize():], nil)
	if err != nil {
		return fmt.Errorf("decrypt configuration: %w", err)
	}
	return json.Unmarshal(plain, target)
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
