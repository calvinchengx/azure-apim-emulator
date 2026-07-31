// Package store persists canonical APIM resources in pure-Go SQLite.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound means the requested resource does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a uniqueness or state constraint was violated.
	ErrConflict = errors.New("conflict")
)

// Store wraps the database and controlled clock.
type Store struct {
	db    *sql.DB
	Clock *clock.Clock
}

var (
	openDB          = sql.Open
	readRandom      = rand.Read
	beginReleaseTxn = func(db *sql.DB) (*sql.Tx, error) { return db.Begin() }
)

// Open creates or opens the emulator database. Empty dataDir is in-memory.
func Open(dataDir string, ck *clock.Clock) (*Store, error) {
	dsn := "file:apim-" + NewOpaqueID() + "?mode=memory&cache=shared"
	if dataDir != "" {
		dsn = filepath.Join(dataDir, "azure-apim-emulator.db")
	}
	db, err := openDB("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Clock: ck}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes SQLite.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL, resource_group TEXT NOT NULL,
	  name TEXT NOT NULL, location TEXT NOT NULL, sku_name TEXT NOT NULL,
	  sku_capacity INTEGER NOT NULL, publisher_name TEXT NOT NULL, publisher_email TEXT NOT NULL,
	  provisioning_state TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_documents (
  id TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apis (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, path TEXT NOT NULL,
  service_url TEXT NOT NULL, protocols_json TEXT NOT NULL,
  subscription_required INTEGER NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_documents (
  api_id TEXT PRIMARY KEY REFERENCES apis(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_revision_metadata (
  api_id TEXT PRIMARY KEY REFERENCES apis(id) ON DELETE CASCADE,
  revision TEXT NOT NULL, description TEXT NOT NULL, is_current INTEGER NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_definitions (
  api_id TEXT PRIMARY KEY REFERENCES apis(id) ON DELETE CASCADE,
  format TEXT NOT NULL, value TEXT NOT NULL, source_url TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_version_sets (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, versioning_scheme TEXT NOT NULL,
  version_header_name TEXT NOT NULL, version_query_name TEXT NOT NULL,
  description TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_version_set_documents (
  version_set_id TEXT PRIMARY KEY REFERENCES api_version_sets(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_version_metadata (
  api_id TEXT PRIMARY KEY REFERENCES apis(id) ON DELETE CASCADE,
  version TEXT NOT NULL, version_set_id TEXT REFERENCES api_version_sets(id) ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS named_values (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, value TEXT NOT NULL, tags_json TEXT NOT NULL,
  secret INTEGER NOT NULL, key_vault_secret_id TEXT NOT NULL,
  key_vault_identity_id TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS named_value_documents (
  named_value_id TEXT PRIMARY KEY REFERENCES named_values(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_named_values_service_display_name
  ON named_values(service_id, display_name COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS backends (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, url TEXT NOT NULL,
  protocol TEXT NOT NULL, resource_id TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, subject TEXT NOT NULL, thumbprint TEXT NOT NULL, expiration INTEGER NOT NULL,
  data BLOB NOT NULL, password TEXT NOT NULL, key_vault_secret_id TEXT NOT NULL,
  key_vault_identity_id TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_releases (
  id TEXT PRIMARY KEY, api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  name TEXT NOT NULL, target_api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  notes TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_release_documents (
  release_id TEXT PRIMARY KEY REFERENCES api_releases(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY, api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, method TEXT NOT NULL,
  url_template TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operation_documents (
  operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_schemas (
  id TEXT PRIMARY KEY, api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  name TEXT NOT NULL, content_type TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tags (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tag_documents (
  tag_id TEXT PRIMARY KEY REFERENCES tags(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_tags (
  resource_id TEXT NOT NULL, tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (resource_id, tag_id)
);
CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, description TEXT NOT NULL, type TEXT NOT NULL,
  external_id TEXT NOT NULL, built_in INTEGER NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_documents (
  group_id TEXT PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
  email TEXT NOT NULL COLLATE NOCASE, state TEXT NOT NULL, note TEXT NOT NULL,
  identities_json TEXT NOT NULL, registration_at INTEGER NOT NULL, password TEXT NOT NULL,
  primary_key TEXT NOT NULL, secondary_key TEXT NOT NULL, etag TEXT NOT NULL,
  UNIQUE(service_id, email)
);
CREATE TABLE IF NOT EXISTS user_documents (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_users (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);
CREATE TABLE IF NOT EXISTS policy_fragments (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, description TEXT NOT NULL, format TEXT NOT NULL, value TEXT NOT NULL,
  provisioning_state TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_fragment_documents (
  fragment_id TEXT PRIMARY KEY REFERENCES policy_fragments(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS loggers (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, logger_type TEXT NOT NULL, description TEXT NOT NULL,
  is_buffered INTEGER NOT NULL, resource_id TEXT NOT NULL, credentials_json TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diagnostics (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  scope_id TEXT NOT NULL, name TEXT NOT NULL, logger_id TEXT NOT NULL,
  always_log TEXT NOT NULL, log_client_ip INTEGER NOT NULL, verbosity TEXT NOT NULL,
  sampling_type TEXT NOT NULL, sampling_percentage REAL NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diagnostic_events (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  api_id TEXT NOT NULL, diagnostic_id TEXT NOT NULL, correlation_id TEXT NOT NULL,
  method TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL,
  timestamp INTEGER NOT NULL, duration_nanos INTEGER NOT NULL, client_ip TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, state TEXT NOT NULL,
  approval_required INTEGER NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product_documents (
  product_id TEXT PRIMARY KEY REFERENCES products(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product_apis (
  product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  PRIMARY KEY (product_id, api_id)
);
CREATE TABLE IF NOT EXISTS product_groups (
  product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  PRIMARY KEY (product_id, group_id)
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, scope TEXT NOT NULL,
  state TEXT NOT NULL, primary_key TEXT NOT NULL, secondary_key TEXT NOT NULL,
  etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subscription_documents (
  subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
  scope_id TEXT PRIMARY KEY, format TEXT NOT NULL, value TEXT NOT NULL, etag TEXT NOT NULL
);
`)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// NewOpaqueID returns a lowercase 32-hex identifier.
func NewOpaqueID() string {
	var value [16]byte
	if _, err := readRandom(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}

func newETag() string { return `"` + NewOpaqueID() + `"` }

// UpsertService creates or replaces a service.
func (s *Store) UpsertService(v model.Service) (model.Service, error) {
	v.ETag = newETag()
	if v.ProvisioningState == "" {
		v.ProvisioningState = "Succeeded"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO services
	    (id, subscription_id, resource_group, name, location, sku_name, sku_capacity, publisher_name, publisher_email, provisioning_state, etag)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	    ON CONFLICT(id) DO UPDATE SET location=excluded.location, sku_name=excluded.sku_name,
	      sku_capacity=excluded.sku_capacity, publisher_name=excluded.publisher_name,
	      publisher_email=excluded.publisher_email, provisioning_state=excluded.provisioning_state, etag=excluded.etag`,
		v.ID(), v.SubscriptionID, v.ResourceGroup, v.Name, v.Location, v.SKUName,
		v.SKUCapacity, v.PublisherName, v.PublisherEmail, v.ProvisioningState, v.ETag)
	if err != nil {
		return v, err
	}
	for _, group := range []struct{ name, displayName string }{{"administrators", "Administrators"}, {"developers", "Developers"}, {"guests", "Guests"}} {
		if _, err := tx.Exec(`INSERT INTO groups
            (id, service_id, name, display_name, description, type, external_id, built_in, etag)
            VALUES (?, ?, ?, ?, '', 'system', '', 1, ?) ON CONFLICT(id) DO NOTHING`,
			v.ID()+"/groups/"+group.name, v.ID(), group.name, group.displayName, newETag()); err != nil {
			return v, err
		}
	}
	if v.Document != nil {
		document, err := json.Marshal(v.Document)
		if err != nil {
			return v, err
		}
		if _, err := tx.Exec(`INSERT INTO resource_documents (id, document_json) VALUES (?, ?)
		    ON CONFLICT(id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
			return v, err
		}
	}
	return v, tx.Commit()
}

// GetService finds one service by ARM ID.
func (s *Store) GetService(id string) (model.Service, error) {
	var v model.Service
	var document string
	err := s.db.QueryRow(`SELECT subscription_id, resource_group, name, location, sku_name,
	      sku_capacity, publisher_name, publisher_email, provisioning_state, etag,
	      COALESCE((SELECT document_json FROM resource_documents WHERE lower(resource_documents.id)=lower(services.id)), '')
	      FROM services WHERE lower(id)=lower(?)`, id).
		Scan(&v.SubscriptionID, &v.ResourceGroup, &v.Name, &v.Location, &v.SKUName,
			&v.SKUCapacity, &v.PublisherName, &v.PublisherEmail, &v.ProvisioningState, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	if err == nil && document != "" {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// DeleteService removes a service and its children.
func (s *Store) DeleteService(id string) error {
	return deleteScopedResource(s.db, "services", id)
}

// ListServices returns services in stable ID order.
func (s *Store) ListServices() ([]model.Service, error) {
	rows, err := s.db.Query(`SELECT subscription_id, resource_group, name, location, sku_name,
	      sku_capacity, publisher_name, publisher_email, provisioning_state, etag,
	      COALESCE((SELECT document_json FROM resource_documents WHERE resource_documents.id=services.id), '')
	      FROM services ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Service
	for rows.Next() {
		var v model.Service
		var document string
		if err := rows.Scan(&v.SubscriptionID, &v.ResourceGroup, &v.Name, &v.Location,
			&v.SKUName, &v.SKUCapacity, &v.PublisherName, &v.PublisherEmail,
			&v.ProvisioningState, &v.ETag, &document); err != nil {
			return nil, err
		}
		if document != "" {
			_ = json.Unmarshal([]byte(document), &v.Document)
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// UpsertAPI creates or replaces an API.
func (s *Store) UpsertAPI(v model.API) (model.API, error) {
	if err := s.validateAPIVersionSet(v); err != nil {
		return v, err
	}
	v.ETag = newETag()
	if v.Revision == "" {
		_, v.Revision = splitRevision(v.Name)
		v.IsCurrent = !strings.Contains(strings.ToLower(v.Name), ";rev=")
	}
	now := s.Clock.Now()
	if v.CreatedAt == 0 {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	protocols, _ := json.Marshal(v.Protocols)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO apis
    (id, service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, path=excluded.path,
      service_url=excluded.service_url, protocols_json=excluded.protocols_json,
      subscription_required=excluded.subscription_required, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, strings.Trim(v.Path, "/"), v.ServiceURL,
		string(protocols), v.SubscriptionRequired, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_documents (api_id, document_json) VALUES (?, ?)
      ON CONFLICT(api_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	_, err = tx.Exec(`INSERT INTO api_revision_metadata
	    (api_id, revision, description, is_current, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
	    ON CONFLICT(api_id) DO UPDATE SET revision=excluded.revision, description=excluded.description,
	      is_current=excluded.is_current, updated_at=excluded.updated_at`,
		v.ID(), v.Revision, v.RevisionDescription, v.IsCurrent, v.CreatedAt, v.UpdatedAt)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_version_metadata (api_id, version, version_set_id)
	    VALUES (?, ?, NULLIF(?, '')) ON CONFLICT(api_id) DO UPDATE SET
	      version=excluded.version, version_set_id=excluded.version_set_id`, v.ID(), v.Version, v.VersionSetID); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// ImportAPI atomically replaces an API, its imported operations, schema, and retained definition.
func (s *Store) ImportAPI(v model.API, definition model.APIDefinition, operations []model.Operation, schema *model.APISchema) (model.API, error) {
	if err := s.validateAPIVersionSet(v); err != nil {
		return v, err
	}
	v.ETag = newETag()
	if v.Revision == "" {
		_, v.Revision = splitRevision(v.Name)
		v.IsCurrent = !strings.Contains(strings.ToLower(v.Name), ";rev=")
	}
	now := s.Clock.Now()
	if v.CreatedAt == 0 {
		v.CreatedAt = now
	}
	v.UpdatedAt = now
	protocols, _ := json.Marshal(v.Protocols)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO apis
      (id, service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
        display_name=excluded.display_name, path=excluded.path, service_url=excluded.service_url,
        protocols_json=excluded.protocols_json, subscription_required=excluded.subscription_required, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, strings.Trim(v.Path, "/"), v.ServiceURL,
		string(protocols), v.SubscriptionRequired, v.ETag); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_documents (api_id, document_json) VALUES (?, ?)
      ON CONFLICT(api_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_revision_metadata
	  (api_id, revision, description, is_current, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(api_id) DO UPDATE SET revision=excluded.revision, description=excluded.description,
        is_current=excluded.is_current, updated_at=excluded.updated_at`, v.ID(), v.Revision,
		v.RevisionDescription, v.IsCurrent, v.CreatedAt, v.UpdatedAt); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_version_metadata (api_id, version, version_set_id)
      VALUES (?, ?, NULLIF(?, '')) ON CONFLICT(api_id) DO UPDATE SET
        version=excluded.version, version_set_id=excluded.version_set_id`, v.ID(), v.Version, v.VersionSetID); err != nil {
		return v, err
	}
	definition.APIID, definition.ETag = v.ID(), newETag()
	if _, err := tx.Exec(`INSERT INTO api_definitions (api_id, format, value, source_url, etag)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(api_id) DO UPDATE SET format=excluded.format,
        value=excluded.value, source_url=excluded.source_url, etag=excluded.etag`, definition.APIID,
		definition.Format, definition.Value, definition.SourceURL, definition.ETag); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`DELETE FROM operations WHERE lower(api_id)=lower(?)`, v.ID()); err != nil {
		return v, err
	}
	for _, operation := range operations {
		operation.APIID, operation.ETag = v.ID(), newETag()
		operationDocument, err := json.Marshal(operation.Document)
		if err != nil {
			return v, err
		}
		if _, err := tx.Exec(`INSERT INTO operations
          (id, api_id, name, display_name, method, url_template, etag) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			operation.APIID+"/operations/"+operation.Name, operation.APIID, operation.Name,
			operation.DisplayName, strings.ToUpper(operation.Method), operation.URLTemplate, operation.ETag); err != nil {
			return v, err
		}
		if _, err := tx.Exec(`INSERT INTO operation_documents (operation_id, document_json) VALUES (?, ?)`,
			operation.APIID+"/operations/"+operation.Name, operationDocument); err != nil {
			return v, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM api_schemas WHERE lower(id)=lower(?)`, v.ID()+"/schemas/openapi"); err != nil {
		return v, err
	}
	if schema != nil {
		document, err := json.Marshal(schema.Document)
		if err != nil {
			return v, err
		}
		schema.APIID, schema.Name, schema.ETag = v.ID(), "openapi", newETag()
		if _, err := tx.Exec(`INSERT INTO api_schemas (id, api_id, name, content_type, document_json, etag)
          VALUES (?, ?, ?, ?, ?, ?)`, schema.ID(), schema.APIID, schema.Name, schema.ContentType, document, schema.ETag); err != nil {
			return v, err
		}
	}
	return v, tx.Commit()
}

// GetAPIDefinition returns the retained source document for an imported API.
func (s *Store) GetAPIDefinition(apiID string) (model.APIDefinition, error) {
	var v model.APIDefinition
	err := s.db.QueryRow(`SELECT api_id, format, value, source_url, etag FROM api_definitions WHERE lower(api_id)=lower(?)`, apiID).
		Scan(&v.APIID, &v.Format, &v.Value, &v.SourceURL, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIDefinition{}, ErrNotFound
	}
	return v, err
}

// CloneAPIRevision atomically creates a revision and copies runtime-owned children.
func (s *Store) CloneAPIRevision(sourceID string, v model.API) (model.API, error) {
	if err := s.validateAPIVersionSet(v); err != nil {
		return v, err
	}
	if v.Revision == "" {
		_, v.Revision = splitRevision(v.Name)
	}
	v.IsCurrent = false
	v.ETag = newETag()
	now := s.Clock.Now()
	v.CreatedAt, v.UpdatedAt = now, now
	protocols, _ := json.Marshal(v.Protocols)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO apis
	    (id, service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, v.ID(), v.ServiceID, v.Name, v.DisplayName,
		strings.Trim(v.Path, "/"), v.ServiceURL, string(protocols), v.SubscriptionRequired, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_documents (api_id, document_json) VALUES (?, ?)`, v.ID(), document); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_revision_metadata
	    (api_id, revision, description, is_current, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		v.ID(), v.Revision, v.RevisionDescription, false, now, now); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_version_metadata (api_id, version, version_set_id)
	    VALUES (?, ?, NULLIF(?, ''))`, v.ID(), v.Version, v.VersionSetID); err != nil {
		return v, err
	}
	childETag := newETag()
	if _, err := tx.Exec(`INSERT INTO operations (id, api_id, name, display_name, method, url_template, etag)
	    SELECT ? || '/operations/' || name, ?, name, display_name, method, url_template, ?
	    FROM operations WHERE lower(api_id)=lower(?)`, v.ID(), v.ID(), childETag, sourceID); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO operation_documents (operation_id, document_json)
	    SELECT ? || substr(operation_id, length(?) + 1), document_json
	    FROM operation_documents WHERE lower(operation_id) LIKE lower(?)`,
		v.ID(), sourceID, sourceID+"/operations/%"); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_schemas (id, api_id, name, content_type, document_json, etag)
	    SELECT ? || '/schemas/' || name, ?, name, content_type, document_json, ?
	    FROM api_schemas WHERE lower(api_id)=lower(?)`, v.ID(), v.ID(), newETag(), sourceID); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_definitions (api_id, format, value, source_url, etag)
      SELECT ?, format, value, source_url, ? FROM api_definitions WHERE lower(api_id)=lower(?)`,
		v.ID(), newETag(), sourceID); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO resource_tags (resource_id, tag_id)
	    SELECT CASE WHEN lower(resource_id)=lower(?) THEN ? ELSE ? || substr(resource_id, length(?) + 1) END, tag_id
	    FROM resource_tags WHERE lower(resource_id)=lower(?) OR lower(resource_id) LIKE lower(?)`,
		sourceID, v.ID(), v.ID(), sourceID, sourceID, sourceID+"/operations/%"); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO diagnostics
        (id, service_id, scope_id, name, logger_id, always_log, log_client_ip, verbosity,
         sampling_type, sampling_percentage, document_json, etag)
        SELECT ? || '/diagnostics/' || name, service_id, ?, name, logger_id, always_log,
          log_client_ip, verbosity, sampling_type, sampling_percentage, document_json, ?
        FROM diagnostics WHERE lower(scope_id)=lower(?)`, v.ID(), v.ID(), newETag(), sourceID); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO policies (scope_id, format, value, etag)
	    SELECT ?, format, value, ? FROM policies WHERE lower(scope_id)=lower(?)`, v.ID(), newETag(), sourceID); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetAPI finds one API by ARM ID.
func (s *Store) GetAPI(id string) (model.API, error) {
	var v model.API
	var protocols, document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, path, service_url,
	      protocols_json, subscription_required, etag,
	      COALESCE((SELECT revision FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), '1'),
	      COALESCE((SELECT description FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), ''),
	      COALESCE((SELECT is_current FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), 1),
	      COALESCE((SELECT created_at FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), 0),
	      COALESCE((SELECT updated_at FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), 0),
	      COALESCE((SELECT version FROM api_version_metadata WHERE lower(api_id)=lower(apis.id)), ''),
	      COALESCE((SELECT version_set_id FROM api_version_metadata WHERE lower(api_id)=lower(apis.id)), ''),
	      COALESCE((SELECT document_json FROM api_documents WHERE lower(api_id)=lower(apis.id)), '{}')
	      FROM apis WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Path, &v.ServiceURL,
			&protocols, &v.SubscriptionRequired, &v.ETag, &v.Revision, &v.RevisionDescription,
			&v.IsCurrent, &v.CreatedAt, &v.UpdatedAt, &v.Version, &v.VersionSetID, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.API{}, ErrNotFound
	}
	if err != nil {
		return model.API{}, err
	}
	_ = json.Unmarshal([]byte(protocols), &v.Protocols)
	_ = json.Unmarshal([]byte(document), &v.Document)
	return v, nil
}

// ListAPIs returns APIs belonging to a service in stable ID order.
func (s *Store) ListAPIs(serviceID string) ([]model.API, error) {
	values, err := scanAPIs(s.db)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.API, 0)
	for _, value := range values {
		if equalID(value.ServiceID, serviceID) {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

// ListAPIRevisions returns every revision belonging to a logical API.
func (s *Store) ListAPIRevisions(serviceID, apiName string) ([]model.API, error) {
	values, err := s.ListAPIs(serviceID)
	if err != nil {
		return nil, err
	}
	wanted, _ := splitRevision(apiName)
	filtered := make([]model.API, 0)
	for _, value := range values {
		base, _ := splitRevision(value.Name)
		if equalID(base, wanted) {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

// UpsertAPIRelease records a release and atomically promotes its target revision.
func (s *Store) UpsertAPIRelease(v model.APIRelease) (model.APIRelease, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	target, err := s.GetAPI(v.TargetAPIID)
	if err != nil {
		return v, err
	}
	parentBase, _ := splitRevision(strings.TrimPrefix(v.APIID, target.ServiceID+"/apis/"))
	targetBase, _ := splitRevision(target.Name)
	if !equalID(parentBase, targetBase) {
		return v, ErrConflict
	}
	now := s.Clock.Now()
	if existing, existingErr := s.GetAPIRelease(v.ID()); existingErr == nil {
		v.CreatedAt = existing.CreatedAt
	} else if !errors.Is(existingErr, ErrNotFound) {
		return v, existingErr
	}
	if v.CreatedAt == 0 {
		v.CreatedAt = now
	}
	v.UpdatedAt, v.ETag = now, newETag()
	tx, err := beginReleaseTxn(s.db)
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO api_releases
	    (id, api_id, name, target_api_id, notes, created_at, updated_at, etag) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	    ON CONFLICT(id) DO UPDATE SET target_api_id=excluded.target_api_id, notes=excluded.notes,
	      updated_at=excluded.updated_at, etag=excluded.etag`, v.ID(), v.APIID, v.Name,
		v.TargetAPIID, v.Notes, v.CreatedAt, v.UpdatedAt, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_release_documents (release_id, document_json) VALUES (?, ?)
	    ON CONFLICT(release_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	result, err := tx.Exec(`UPDATE api_revision_metadata SET is_current=CASE WHEN lower(api_id)=lower(?) THEN 1 ELSE 0 END
	    WHERE api_id IN (SELECT id FROM apis WHERE lower(service_id)=lower(?) AND
	      (lower(name)=lower(?) OR lower(name) LIKE lower(?)))`, v.TargetAPIID, target.ServiceID,
		targetBase, targetBase+";rev=%")
	if err != nil {
		return v, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return v, ErrNotFound
	}
	return v, tx.Commit()
}

// GetAPIRelease finds one API release.
func (s *Store) GetAPIRelease(id string) (model.APIRelease, error) {
	var v model.APIRelease
	var document string
	err := s.db.QueryRow(`SELECT api_id, name, target_api_id, notes, created_at, updated_at, etag,
	    COALESCE((SELECT document_json FROM api_release_documents WHERE lower(release_id)=lower(api_releases.id)), '{}')
	    FROM api_releases WHERE lower(id)=lower(?)`, id).
		Scan(&v.APIID, &v.Name, &v.TargetAPIID, &v.Notes, &v.CreatedAt, &v.UpdatedAt, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIRelease{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAPIReleases returns releases for an API in stable ID order.
func (s *Store) ListAPIReleases(apiID string) ([]model.APIRelease, error) {
	rows, err := s.db.Query(`SELECT api_id, name, target_api_id, notes, created_at, updated_at, etag,
	    COALESCE((SELECT document_json FROM api_release_documents WHERE lower(release_id)=lower(api_releases.id)), '{}')
	    FROM api_releases WHERE lower(api_id)=lower(?) ORDER BY id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APIRelease, 0)
	for rows.Next() {
		var v model.APIRelease
		var document string
		if err := rows.Scan(&v.APIID, &v.Name, &v.TargetAPIID, &v.Notes, &v.CreatedAt, &v.UpdatedAt, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAPIRelease removes release history without changing the current revision.
func (s *Store) DeleteAPIRelease(id string) error {
	return deleteScopedResource(s.db, "api_releases", id)
}

// UpsertAPIVersionSet creates or replaces a version set.
func (s *Store) UpsertAPIVersionSet(v model.APIVersionSet) (model.APIVersionSet, error) {
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO api_version_sets
	    (id, service_id, name, display_name, versioning_scheme, version_header_name, version_query_name, description, etag)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,
	      versioning_scheme=excluded.versioning_scheme, version_header_name=excluded.version_header_name,
	      version_query_name=excluded.version_query_name, description=excluded.description, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.VersioningScheme, v.VersionHeaderName,
		v.VersionQueryName, v.Description, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_version_set_documents (version_set_id, document_json) VALUES (?, ?)
	    ON CONFLICT(version_set_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetAPIVersionSet finds one version set.
func (s *Store) GetAPIVersionSet(id string) (model.APIVersionSet, error) {
	var v model.APIVersionSet
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, versioning_scheme,
	    version_header_name, version_query_name, description, etag,
	    COALESCE((SELECT document_json FROM api_version_set_documents WHERE lower(version_set_id)=lower(api_version_sets.id)), '{}')
	    FROM api_version_sets WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.VersioningScheme, &v.VersionHeaderName,
			&v.VersionQueryName, &v.Description, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIVersionSet{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAPIVersionSets returns version sets for a service in stable ID order.
func (s *Store) ListAPIVersionSets(serviceID string) ([]model.APIVersionSet, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, versioning_scheme,
	    version_header_name, version_query_name, description, etag,
	    COALESCE((SELECT document_json FROM api_version_set_documents WHERE lower(version_set_id)=lower(api_version_sets.id)), '{}')
	    FROM api_version_sets
	    WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APIVersionSet, 0)
	for rows.Next() {
		var v model.APIVersionSet
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.VersioningScheme,
			&v.VersionHeaderName, &v.VersionQueryName, &v.Description, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAPIVersionSet removes an unused version set.
func (s *Store) DeleteAPIVersionSet(id string) error {
	return deleteScopedResource(s.db, "api_version_sets", id)
}

// UpsertNamedValue creates or replaces a named value.
func (s *Store) UpsertNamedValue(v model.NamedValue) (model.NamedValue, error) {
	sanitizeNamedValueDocument(v.Document)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	tags, _ := json.Marshal(v.Tags)
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO named_values
        (id, service_id, name, display_name, value, tags_json, secret, key_vault_secret_id, key_vault_identity_id, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
          display_name=excluded.display_name, value=excluded.value, tags_json=excluded.tags_json,
          secret=excluded.secret, key_vault_secret_id=excluded.key_vault_secret_id,
          key_vault_identity_id=excluded.key_vault_identity_id, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Value, string(tags), v.Secret,
		v.KeyVaultSecretID, v.KeyVaultIdentityID, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO named_value_documents (named_value_id, document_json) VALUES (?, ?)
	    ON CONFLICT(named_value_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

func sanitizeNamedValueDocument(document map[string]any) {
	delete(document, "value")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "value")
}

// GetNamedValue finds one named value.
func (s *Store) GetNamedValue(id string) (model.NamedValue, error) {
	var v model.NamedValue
	var tags, document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, value, tags_json, secret,
		key_vault_secret_id, key_vault_identity_id, etag,
		COALESCE((SELECT document_json FROM named_value_documents WHERE lower(named_value_id)=lower(named_values.id)), '{}')
		FROM named_values WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Value, &tags, &v.Secret,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.NamedValue{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(tags), &v.Tags)
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListNamedValues returns named values for a service in stable ID order.
func (s *Store) ListNamedValues(serviceID string) ([]model.NamedValue, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, value, tags_json, secret,
		key_vault_secret_id, key_vault_identity_id, etag,
		COALESCE((SELECT document_json FROM named_value_documents WHERE lower(named_value_id)=lower(named_values.id)), '{}')
		FROM named_values
        WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.NamedValue, 0)
	for rows.Next() {
		var v model.NamedValue
		var tags, document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Value, &tags, &v.Secret,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &v.Tags)
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteNamedValue removes a named value.
func (s *Store) DeleteNamedValue(id string) error {
	return deleteScopedResource(s.db, "named_values", id)
}

// UpsertBackend creates or replaces a backend.
func (s *Store) UpsertBackend(v model.Backend) (model.Backend, error) {
	v.ETag = newETag()
	document, _ := json.Marshal(v.Document)
	_, err := s.db.Exec(`INSERT INTO backends
        (id, service_id, name, title, description, url, protocol, resource_id, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,
          description=excluded.description, url=excluded.url, protocol=excluded.protocol,
          resource_id=excluded.resource_id, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.Title, v.Description, v.URL, v.Protocol, v.ResourceID, string(document), v.ETag)
	return v, err
}

// GetBackend finds one backend.
func (s *Store) GetBackend(id string) (model.Backend, error) {
	var v model.Backend
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, title, description, url, protocol, resource_id,
        document_json, etag FROM backends WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.Title, &v.Description, &v.URL, &v.Protocol, &v.ResourceID, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Backend{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListBackends returns backends for a service in stable ID order.
func (s *Store) ListBackends(serviceID string) ([]model.Backend, error) {
	rows, err := s.db.Query(`SELECT service_id, name, title, description, url, protocol, resource_id,
        document_json, etag FROM backends WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Backend, 0)
	for rows.Next() {
		var v model.Backend
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Title, &v.Description, &v.URL, &v.Protocol,
			&v.ResourceID, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteBackend removes a backend.
func (s *Store) DeleteBackend(id string) error { return deleteScopedResource(s.db, "backends", id) }

// UpsertAPISchema creates or replaces an API schema.
func (s *Store) UpsertAPISchema(v model.APISchema) (model.APISchema, error) {
	v.ETag = newETag()
	document, _ := json.Marshal(v.Document)
	_, err := s.db.Exec(`INSERT INTO api_schemas (id, api_id, name, content_type, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET content_type=excluded.content_type,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.APIID, v.Name, v.ContentType, string(document), v.ETag)
	return v, err
}

// GetAPISchema finds one API schema.
func (s *Store) GetAPISchema(id string) (model.APISchema, error) {
	var v model.APISchema
	var document string
	err := s.db.QueryRow(`SELECT api_id, name, content_type, document_json, etag
        FROM api_schemas WHERE lower(id)=lower(?)`, id).Scan(&v.APIID, &v.Name, &v.ContentType, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APISchema{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAPISchemas returns schemas for an API in stable ID order.
func (s *Store) ListAPISchemas(apiID string) ([]model.APISchema, error) {
	rows, err := s.db.Query(`SELECT api_id, name, content_type, document_json, etag
        FROM api_schemas WHERE lower(api_id)=lower(?) ORDER BY id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APISchema, 0)
	for rows.Next() {
		var v model.APISchema
		var document string
		if err := rows.Scan(&v.APIID, &v.Name, &v.ContentType, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAPISchema removes an API schema.
func (s *Store) DeleteAPISchema(id string) error {
	return deleteScopedResource(s.db, "api_schemas", id)
}

// UpsertTag creates or replaces a service tag.
func (s *Store) UpsertTag(v model.Tag) (model.Tag, error) {
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO tags (id, service_id, name, display_name, etag) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO tag_documents (tag_id, document_json) VALUES (?, ?)
	    ON CONFLICT(tag_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetTag finds one service tag.
func (s *Store) GetTag(id string) (model.Tag, error) {
	var v model.Tag
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, etag,
	    COALESCE((SELECT document_json FROM tag_documents WHERE lower(tag_id)=lower(tags.id)), '{}')
	    FROM tags WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Tag{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListTags returns tags for a service in stable ID order.
func (s *Store) ListTags(serviceID string) ([]model.Tag, error) {
	return scanTags(s.db.Query(`SELECT service_id, name, display_name, etag,
	    COALESCE((SELECT document_json FROM tag_documents WHERE lower(tag_id)=lower(tags.id)), '{}')
	    FROM tags WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

// DeleteTag removes a tag and all associations.
func (s *Store) DeleteTag(id string) error { return deleteScopedResource(s.db, "tags", id) }

// AssignTag associates an existing tag with a resource.
func (s *Store) AssignTag(resourceID, tagID string) error {
	_, err := s.db.Exec(`INSERT INTO resource_tags (resource_id, tag_id) VALUES (?, ?)
        ON CONFLICT(resource_id, tag_id) DO NOTHING`, resourceID, tagID)
	return err
}

// DetachTag removes a resource association idempotently.
func (s *Store) DetachTag(resourceID, tagID string) error {
	_, err := s.db.Exec(`DELETE FROM resource_tags WHERE lower(resource_id)=lower(?) AND lower(tag_id)=lower(?)`, resourceID, tagID)
	return err
}

// GetResourceTag returns one associated tag.
func (s *Store) GetResourceTag(resourceID, tagID string) (model.Tag, error) {
	values, err := scanTags(s.db.Query(`SELECT tags.service_id, tags.name, tags.display_name, tags.etag,
	    COALESCE((SELECT document_json FROM tag_documents WHERE lower(tag_id)=lower(tags.id)), '{}')
        FROM tags JOIN resource_tags ON lower(resource_tags.tag_id)=lower(tags.id)
        WHERE lower(resource_tags.resource_id)=lower(?) AND lower(tags.id)=lower(?)`, resourceID, tagID))
	if err != nil {
		return model.Tag{}, err
	}
	if len(values) == 0 {
		return model.Tag{}, ErrNotFound
	}
	return values[0], nil
}

// ListResourceTags returns associated tags in stable ID order.
func (s *Store) ListResourceTags(resourceID string) ([]model.Tag, error) {
	return scanTags(s.db.Query(`SELECT tags.service_id, tags.name, tags.display_name, tags.etag,
	    COALESCE((SELECT document_json FROM tag_documents WHERE lower(tag_id)=lower(tags.id)), '{}')
        FROM tags JOIN resource_tags ON lower(resource_tags.tag_id)=lower(tags.id)
        WHERE lower(resource_tags.resource_id)=lower(?) ORDER BY tags.id`, resourceID))
}

func scanTags(rows *sql.Rows, err error) ([]model.Tag, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Tag, 0)
	for rows.Next() {
		var v model.Tag
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// UpsertGroup creates or replaces a service group.
func (s *Store) UpsertGroup(v model.Group) (model.Group, error) {
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO groups
        (id, service_id, name, display_name, description, type, external_id, built_in, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
          display_name=excluded.display_name, description=excluded.description, type=excluded.type,
          external_id=excluded.external_id, built_in=excluded.built_in, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Description, v.Type, v.ExternalID, v.BuiltIn, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO group_documents (group_id, document_json) VALUES (?, ?)
	    ON CONFLICT(group_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetGroup finds one service group.
func (s *Store) GetGroup(id string) (model.Group, error) {
	values, err := scanGroups(s.db.Query(`SELECT service_id, name, display_name, description, type, external_id, built_in, etag,
	    COALESCE((SELECT document_json FROM group_documents WHERE lower(group_id)=lower(groups.id)), '{}')
        FROM groups WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.Group{}, err
	}
	if len(values) == 0 {
		return model.Group{}, ErrNotFound
	}
	return values[0], nil
}

// ListGroups returns groups for a service in stable ID order.
func (s *Store) ListGroups(serviceID string) ([]model.Group, error) {
	return scanGroups(s.db.Query(`SELECT service_id, name, display_name, description, type, external_id, built_in, etag,
	    COALESCE((SELECT document_json FROM group_documents WHERE lower(group_id)=lower(groups.id)), '{}')
        FROM groups WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

// DeleteGroup removes a group and its relationships.
func (s *Store) DeleteGroup(id string) error { return deleteScopedResource(s.db, "groups", id) }

// LinkProductGroup associates an existing group with an existing product.
func (s *Store) LinkProductGroup(productID, groupID string) error {
	_, err := s.db.Exec(`INSERT INTO product_groups (product_id, group_id) VALUES (?, ?)
        ON CONFLICT(product_id, group_id) DO NOTHING`, productID, groupID)
	return err
}

// UnlinkProductGroup removes a product-group association idempotently.
func (s *Store) UnlinkProductGroup(productID, groupID string) error {
	_, err := s.db.Exec(`DELETE FROM product_groups WHERE lower(product_id)=lower(?) AND lower(group_id)=lower(?)`, productID, groupID)
	return err
}

// HasProductGroup reports whether a product-group association exists.
func (s *Store) HasProductGroup(productID, groupID string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM product_groups WHERE lower(product_id)=lower(?) AND lower(group_id)=lower(?)`, productID, groupID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ListProductGroups returns groups associated with a product.
func (s *Store) ListProductGroups(productID string) ([]model.Group, error) {
	return scanGroups(s.db.Query(`SELECT groups.service_id, groups.name, groups.display_name, groups.description,
	    groups.type, groups.external_id, groups.built_in, groups.etag,
	    COALESCE((SELECT document_json FROM group_documents WHERE lower(group_id)=lower(groups.id)), '{}') FROM groups
        JOIN product_groups ON lower(product_groups.group_id)=lower(groups.id)
        WHERE lower(product_groups.product_id)=lower(?) ORDER BY groups.id`, productID))
}

func scanGroups(rows *sql.Rows, err error) ([]model.Group, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Group, 0)
	for rows.Next() {
		var v model.Group
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Description, &v.Type, &v.ExternalID, &v.BuiltIn, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// UpsertUser creates or replaces a service user.
func (s *Store) UpsertUser(v model.User) (model.User, error) {
	sanitizeUserDocument(v.Document)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	if v.RegistrationAt == 0 {
		v.RegistrationAt = s.Clock.Now()
	}
	if v.Password == "" {
		v.Password = NewOpaqueID()
	}
	if v.PrimaryKey == "" {
		v.PrimaryKey = NewOpaqueID()
	}
	if v.SecondaryKey == "" {
		v.SecondaryKey = NewOpaqueID()
	}
	v.ETag = newETag()
	identities, _ := json.Marshal(v.Identities)
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO users
        (id, service_id, name, first_name, last_name, email, state, note, identities_json,
         registration_at, password, primary_key, secondary_key, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
          first_name=excluded.first_name, last_name=excluded.last_name, email=excluded.email,
          state=excluded.state, note=excluded.note, identities_json=excluded.identities_json,
          password=excluded.password, primary_key=excluded.primary_key, secondary_key=excluded.secondary_key,
          etag=excluded.etag`, v.ID(), v.ServiceID, v.Name, v.FirstName, v.LastName, v.Email,
		v.State, v.Note, identities, v.RegistrationAt, v.Password, v.PrimaryKey, v.SecondaryKey, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO user_documents (user_id, document_json) VALUES (?, ?)
	    ON CONFLICT(user_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

func sanitizeUserDocument(document map[string]any) {
	delete(document, "password")
	delete(document, "primaryKey")
	delete(document, "secondaryKey")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "password")
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
}

// GetUser finds one service user.
func (s *Store) GetUser(id string) (model.User, error) {
	values, err := scanUsers(s.db.Query(`SELECT service_id, name, first_name, last_name, email, state, note,
		identities_json, registration_at, password, primary_key, secondary_key, etag,
		COALESCE((SELECT document_json FROM user_documents WHERE lower(user_id)=lower(users.id)), '{}')
		FROM users WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.User{}, err
	}
	if len(values) == 0 {
		return model.User{}, ErrNotFound
	}
	return values[0], nil
}

// ListUsers returns users for a service in stable ID order.
func (s *Store) ListUsers(serviceID string) ([]model.User, error) {
	return scanUsers(s.db.Query(`SELECT service_id, name, first_name, last_name, email, state, note,
		identities_json, registration_at, password, primary_key, secondary_key, etag,
		COALESCE((SELECT document_json FROM user_documents WHERE lower(user_id)=lower(users.id)), '{}')
		FROM users WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

// DeleteUser removes a user and its memberships.
func (s *Store) DeleteUser(id string) error { return deleteScopedResource(s.db, "users", id) }

// LinkGroupUser associates an existing user with an existing group.
func (s *Store) LinkGroupUser(groupID, userID string) error {
	_, err := s.db.Exec(`INSERT INTO group_users (group_id, user_id) VALUES (?, ?)
        ON CONFLICT(group_id, user_id) DO NOTHING`, groupID, userID)
	return err
}

// UnlinkGroupUser removes a group membership idempotently.
func (s *Store) UnlinkGroupUser(groupID, userID string) error {
	_, err := s.db.Exec(`DELETE FROM group_users WHERE lower(group_id)=lower(?) AND lower(user_id)=lower(?)`, groupID, userID)
	return err
}

// HasGroupUser reports whether a membership exists.
func (s *Store) HasGroupUser(groupID, userID string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM group_users WHERE lower(group_id)=lower(?) AND lower(user_id)=lower(?)`, groupID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ListGroupUsers returns users associated with a group.
func (s *Store) ListGroupUsers(groupID string) ([]model.User, error) {
	return scanUsers(s.db.Query(`SELECT users.service_id, users.name, users.first_name, users.last_name,
		users.email, users.state, users.note, users.identities_json, users.registration_at,
		users.password, users.primary_key, users.secondary_key, users.etag,
		COALESCE((SELECT document_json FROM user_documents WHERE lower(user_id)=lower(users.id)), '{}') FROM users
        JOIN group_users ON lower(group_users.user_id)=lower(users.id)
        WHERE lower(group_users.group_id)=lower(?) ORDER BY users.id`, groupID))
}

// ListUserGroups returns groups associated with a user.
func (s *Store) ListUserGroups(userID string) ([]model.Group, error) {
	return scanGroups(s.db.Query(`SELECT groups.service_id, groups.name, groups.display_name, groups.description,
	    groups.type, groups.external_id, groups.built_in, groups.etag,
	    COALESCE((SELECT document_json FROM group_documents WHERE lower(group_id)=lower(groups.id)), '{}') FROM groups
        JOIN group_users ON lower(group_users.group_id)=lower(groups.id)
        WHERE lower(group_users.user_id)=lower(?) ORDER BY groups.id`, userID))
}

func scanUsers(rows *sql.Rows, err error) ([]model.User, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.User, 0)
	for rows.Next() {
		var v model.User
		var identities, document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.FirstName, &v.LastName, &v.Email, &v.State,
			&v.Note, &identities, &v.RegistrationAt, &v.Password, &v.PrimaryKey, &v.SecondaryKey, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(identities), &v.Identities)
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// UpsertPolicyFragment creates or replaces a reusable policy fragment.
func (s *Store) UpsertPolicyFragment(v model.PolicyFragment) (model.PolicyFragment, error) {
	if v.Format == "" {
		v.Format = "xml"
	}
	if v.ProvisioningState == "" {
		v.ProvisioningState = "Succeeded"
	}
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO policy_fragments
        (id, service_id, name, description, format, value, provisioning_state, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET description=excluded.description,
          format=excluded.format, value=excluded.value, provisioning_state=excluded.provisioning_state,
          etag=excluded.etag`, v.ID(), v.ServiceID, v.Name, v.Description, v.Format, v.Value, v.ProvisioningState, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO policy_fragment_documents (fragment_id, document_json) VALUES (?, ?)
	    ON CONFLICT(fragment_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetPolicyFragment finds one policy fragment.
func (s *Store) GetPolicyFragment(id string) (model.PolicyFragment, error) {
	values, err := scanPolicyFragments(s.db.Query(`SELECT service_id, name, description, format, value, provisioning_state, etag,
	    COALESCE((SELECT document_json FROM policy_fragment_documents WHERE lower(fragment_id)=lower(policy_fragments.id)), '{}')
        FROM policy_fragments WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.PolicyFragment{}, err
	}
	if len(values) == 0 {
		return model.PolicyFragment{}, ErrNotFound
	}
	return values[0], nil
}

// ListPolicyFragments returns fragments for a service in stable ID order.
func (s *Store) ListPolicyFragments(serviceID string) ([]model.PolicyFragment, error) {
	return scanPolicyFragments(s.db.Query(`SELECT service_id, name, description, format, value, provisioning_state, etag,
	    COALESCE((SELECT document_json FROM policy_fragment_documents WHERE lower(fragment_id)=lower(policy_fragments.id)), '{}')
        FROM policy_fragments WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

// DeletePolicyFragment removes a policy fragment.
func (s *Store) DeletePolicyFragment(id string) error {
	return deleteScopedResource(s.db, "policy_fragments", id)
}

// ListPolicyFragmentReferences returns policies that include a fragment.
func (s *Store) ListPolicyFragmentReferences(serviceID, name string) ([]model.Policy, error) {
	patternDouble := `%fragment-id="` + name + `"%`
	patternSingle := `%fragment-id='` + name + `'%`
	rows, err := s.db.Query(`SELECT scope_id, format, value, etag FROM policies
        WHERE (lower(scope_id)=lower(?) OR lower(scope_id) LIKE lower(?))
          AND (lower(value) LIKE lower(?) OR lower(value) LIKE lower(?)) ORDER BY scope_id`,
		serviceID, serviceID+"/%", patternDouble, patternSingle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Policy, 0)
	for rows.Next() {
		var v model.Policy
		if err := rows.Scan(&v.ScopeID, &v.Format, &v.Value, &v.ETag); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanPolicyFragments(rows *sql.Rows, err error) ([]model.PolicyFragment, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.PolicyFragment, 0)
	for rows.Next() {
		var v model.PolicyFragment
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Description, &v.Format, &v.Value, &v.ProvisioningState, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// UpsertCertificate creates or replaces a certificate.
func (s *Store) UpsertCertificate(v model.Certificate) (model.Certificate, error) {
	v.ETag = newETag()
	if v.Data == nil {
		v.Data = []byte{}
	}
	_, err := s.db.Exec(`INSERT INTO certificates
        (id, service_id, name, subject, thumbprint, expiration, data, password, key_vault_secret_id, key_vault_identity_id, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET subject=excluded.subject,
          thumbprint=excluded.thumbprint, expiration=excluded.expiration, data=excluded.data,
          password=excluded.password, key_vault_secret_id=excluded.key_vault_secret_id,
          key_vault_identity_id=excluded.key_vault_identity_id, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.Subject, v.Thumbprint, v.Expiration.Unix(), v.Data, v.Password,
		v.KeyVaultSecretID, v.KeyVaultIdentityID, v.ETag)
	return v, err
}

// GetCertificate finds one certificate.
func (s *Store) GetCertificate(id string) (model.Certificate, error) {
	var v model.Certificate
	var expiration int64
	err := s.db.QueryRow(`SELECT service_id, name, subject, thumbprint, expiration, data, password,
        key_vault_secret_id, key_vault_identity_id, etag FROM certificates WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.Subject, &v.Thumbprint, &expiration, &v.Data, &v.Password,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Certificate{}, ErrNotFound
	}
	if err == nil && expiration != 0 {
		v.Expiration = time.Unix(expiration, 0).UTC()
	}
	return v, err
}

// ListCertificates returns certificates for a service in stable ID order.
func (s *Store) ListCertificates(serviceID string) ([]model.Certificate, error) {
	rows, err := s.db.Query(`SELECT service_id, name, subject, thumbprint, expiration, data, password,
        key_vault_secret_id, key_vault_identity_id, etag FROM certificates
        WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Certificate, 0)
	for rows.Next() {
		var v model.Certificate
		var expiration int64
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Subject, &v.Thumbprint, &expiration, &v.Data,
			&v.Password, &v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.ETag); err != nil {
			return nil, err
		}
		if expiration != 0 {
			v.Expiration = time.Unix(expiration, 0).UTC()
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteCertificate removes a certificate.
func (s *Store) DeleteCertificate(id string) error {
	return deleteScopedResource(s.db, "certificates", id)
}

func (s *Store) validateAPIVersionSet(v model.API) error {
	if v.VersionSetID == "" {
		return nil
	}
	versionSet, err := s.GetAPIVersionSet(v.VersionSetID)
	if err != nil {
		return err
	}
	if !equalID(versionSet.ServiceID, v.ServiceID) {
		return ErrConflict
	}
	return nil
}

// DeleteAPI removes an API and its children.
func (s *Store) DeleteAPI(id string) error {
	return deleteScopedResource(s.db, "apis", id)
}

// UpsertOperation creates or replaces an operation.
func (s *Store) UpsertOperation(v model.Operation) (model.Operation, error) {
	v.ETag = newETag()
	id := v.APIID + "/operations/" + v.Name
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO operations
    (id, api_id, name, display_name, method, url_template, etag) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, method=excluded.method,
      url_template=excluded.url_template, etag=excluded.etag`, id, v.APIID, v.Name,
		v.DisplayName, strings.ToUpper(v.Method), v.URLTemplate, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO operation_documents (operation_id, document_json) VALUES (?, ?)
	    ON CONFLICT(operation_id) DO UPDATE SET document_json=excluded.document_json`, id, document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetOperation finds one operation by ARM ID.
func (s *Store) GetOperation(id string) (model.Operation, error) {
	var v model.Operation
	var document string
	err := s.db.QueryRow(`SELECT api_id, name, display_name, method, url_template, etag,
	    COALESCE((SELECT document_json FROM operation_documents WHERE lower(operation_id)=lower(operations.id)), '{}')
	    FROM operations WHERE lower(id)=lower(?)`, id).
		Scan(&v.APIID, &v.Name, &v.DisplayName, &v.Method, &v.URLTemplate, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Operation{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListOperations returns operations belonging to an API in stable ID order.
func (s *Store) ListOperations(apiID string) ([]model.Operation, error) {
	values, err := scanOperations(s.db)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.Operation, 0)
	for _, value := range values {
		if equalID(value.APIID, apiID) {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

// DeleteOperation removes an operation.
func (s *Store) DeleteOperation(id string) error {
	return deleteScopedResource(s.db, "operations", id)
}

// UpsertProduct creates or replaces a product.
func (s *Store) UpsertProduct(v model.Product) (model.Product, error) {
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO products
    (id, service_id, name, display_name, state, approval_required, etag) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, state=excluded.state,
      approval_required=excluded.approval_required, etag=excluded.etag`, v.ID(), v.ServiceID,
		v.Name, v.DisplayName, v.State, v.ApprovalRequired, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO product_documents (product_id, document_json) VALUES (?, ?)
	    ON CONFLICT(product_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetProduct finds one product by ARM ID.
func (s *Store) GetProduct(id string) (model.Product, error) {
	var v model.Product
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, state, approval_required, etag,
	    COALESCE((SELECT document_json FROM product_documents WHERE lower(product_id)=lower(products.id)), '{}')
	    FROM products WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.State, &v.ApprovalRequired, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Product{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListProducts returns products belonging to a service in stable ID order.
func (s *Store) ListProducts(serviceID string) ([]model.Product, error) {
	values, err := scanProducts(s.db)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.Product, 0)
	for _, value := range values {
		if equalID(value.ServiceID, serviceID) {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

// DeleteProduct removes a product and its associations.
func (s *Store) DeleteProduct(id string) error {
	return deleteScopedResource(s.db, "products", id)
}

// LinkProductAPI associates an API with a product.
func (s *Store) LinkProductAPI(productID, apiID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO product_apis (product_id, api_id) VALUES (?, ?)`, productID, apiID)
	return err
}

// UnlinkProductAPI removes an API association from a product.
func (s *Store) UnlinkProductAPI(productID, apiID string) error {
	result, err := s.db.Exec(`DELETE FROM product_apis WHERE lower(product_id)=lower(?) AND lower(api_id)=lower(?)`, productID, apiID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

// ListProductAPIs returns API IDs associated with a product.
func (s *Store) ListProductAPIs(productID string) ([]string, error) {
	links, err := scanLinks(s.db)
	if err != nil {
		return nil, err
	}
	for owner, values := range links {
		if equalID(owner, productID) {
			return values, nil
		}
	}
	return []string{}, nil
}

// UpsertSubscription creates or replaces a subscription, generating absent keys.
func (s *Store) UpsertSubscription(v model.Subscription) (model.Subscription, error) {
	sanitizeSubscriptionDocument(v.Document)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	if v.PrimaryKey == "" {
		v.PrimaryKey = NewOpaqueID()
	}
	if v.SecondaryKey == "" {
		v.SecondaryKey = NewOpaqueID()
	}
	if v.State == "" {
		v.State = "active"
	}
	v.ETag = newETag()
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO subscriptions
    (id, service_id, name, display_name, scope, state, primary_key, secondary_key, etag)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, scope=excluded.scope,
      state=excluded.state, primary_key=excluded.primary_key, secondary_key=excluded.secondary_key,
      etag=excluded.etag`, v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Scope, v.State,
		v.PrimaryKey, v.SecondaryKey, v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO subscription_documents (subscription_id, document_json) VALUES (?, ?)
	    ON CONFLICT(subscription_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

func sanitizeSubscriptionDocument(document map[string]any) {
	delete(document, "primaryKey")
	delete(document, "secondaryKey")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "primaryKey")
	delete(properties, "secondaryKey")
}

// GetSubscription finds one subscription by ARM ID.
func (s *Store) GetSubscription(id string) (model.Subscription, error) {
	var v model.Subscription
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, scope, state, primary_key, secondary_key, etag,
	    COALESCE((SELECT document_json FROM subscription_documents WHERE lower(subscription_id)=lower(subscriptions.id)), '{}')
	    FROM subscriptions WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Scope, &v.State, &v.PrimaryKey, &v.SecondaryKey, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Subscription{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListSubscriptions returns subscriptions belonging to a service in stable ID order.
func (s *Store) ListSubscriptions(serviceID string) ([]model.Subscription, error) {
	values, err := scanSubscriptions(s.db)
	if err != nil {
		return nil, err
	}
	filtered := make([]model.Subscription, 0)
	for _, value := range values {
		if equalID(value.ServiceID, serviceID) {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

// DeleteSubscription removes a subscription.
func (s *Store) DeleteSubscription(id string) error {
	return deleteScopedResource(s.db, "subscriptions", id)
}

// RegenerateSubscriptionKey replaces one key and advances the subscription ETag.
func (s *Store) RegenerateSubscriptionKey(id string, primary bool) (model.Subscription, error) {
	column := "secondary_key"
	if primary {
		column = "primary_key"
	}
	result, err := s.db.Exec(`UPDATE subscriptions SET `+column+`=?, etag=? WHERE lower(id)=lower(?)`, NewOpaqueID(), newETag(), id)
	if err != nil {
		return model.Subscription{}, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return model.Subscription{}, ErrNotFound
	}
	return s.GetSubscription(id)
}

// UpsertPolicy stores policy XML for a scope.
func (s *Store) UpsertPolicy(v model.Policy) (model.Policy, error) {
	v.ETag = newETag()
	_, err := s.db.Exec(`INSERT INTO policies (scope_id, format, value, etag) VALUES (?, ?, ?, ?)
      ON CONFLICT(scope_id) DO UPDATE SET format=excluded.format, value=excluded.value, etag=excluded.etag`,
		v.ScopeID, v.Format, v.Value, v.ETag)
	return v, err
}

// GetPolicy finds a policy by its owning scope ID.
func (s *Store) GetPolicy(scopeID string) (model.Policy, error) {
	var value model.Policy
	err := s.db.QueryRow(`SELECT scope_id, format, value, etag FROM policies WHERE lower(scope_id)=lower(?)`, scopeID).
		Scan(&value.ScopeID, &value.Format, &value.Value, &value.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Policy{}, ErrNotFound
	}
	if err != nil {
		return model.Policy{}, err
	}
	return value, nil
}

// UpsertLogger creates or replaces a service logger while preserving its ARM document.
func (s *Store) UpsertLogger(v model.Logger) (model.Logger, error) {
	v.ETag = newETag()
	credentials, _ := json.Marshal(v.Credentials)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO loggers
      (id, service_id, name, logger_type, description, is_buffered, resource_id, credentials_json, document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET logger_type=excluded.logger_type, description=excluded.description,
        is_buffered=excluded.is_buffered, resource_id=excluded.resource_id,
        credentials_json=excluded.credentials_json, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.LoggerType, v.Description, v.IsBuffered, v.ResourceID,
		credentials, document, v.ETag)
	return v, err
}

// GetLogger finds one logger by ARM ID.
func (s *Store) GetLogger(id string) (model.Logger, error) {
	values, err := scanLoggers(s.db.Query(`SELECT service_id, name, logger_type, description, is_buffered,
      resource_id, credentials_json, document_json, etag FROM loggers WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.Logger{}, err
	}
	if len(values) == 0 {
		return model.Logger{}, ErrNotFound
	}
	return values[0], nil
}

// ListLoggers returns service loggers in stable ID order.
func (s *Store) ListLoggers(serviceID string) ([]model.Logger, error) {
	return scanLoggers(s.db.Query(`SELECT service_id, name, logger_type, description, is_buffered,
      resource_id, credentials_json, document_json, etag FROM loggers
      WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanLoggers(rows *sql.Rows, err error) ([]model.Logger, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Logger, 0)
	for rows.Next() {
		var v model.Logger
		var credentials, document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.LoggerType, &v.Description, &v.IsBuffered,
			&v.ResourceID, &credentials, &document, &v.ETag); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(credentials), &v.Credentials); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteLogger removes an unreferenced logger.
func (s *Store) DeleteLogger(id string) error {
	var references int
	if err := s.db.QueryRow(`SELECT count(*) FROM diagnostics WHERE lower(logger_id)=lower(?)`, id).Scan(&references); err != nil {
		return err
	}
	if references != 0 {
		return ErrConflict
	}
	return deleteScopedResource(s.db, "loggers", id)
}

// UpsertDiagnostic creates or replaces a diagnostic at service or API scope.
func (s *Store) UpsertDiagnostic(v model.Diagnostic) (model.Diagnostic, error) {
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO diagnostics
      (id, service_id, scope_id, name, logger_id, always_log, log_client_ip, verbosity,
       sampling_type, sampling_percentage, document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET logger_id=excluded.logger_id, always_log=excluded.always_log,
        log_client_ip=excluded.log_client_ip, verbosity=excluded.verbosity,
        sampling_type=excluded.sampling_type, sampling_percentage=excluded.sampling_percentage,
        document_json=excluded.document_json, etag=excluded.etag`, v.ID(), v.ServiceID, v.ScopeID,
		v.Name, v.LoggerID, v.AlwaysLog, v.LogClientIP, v.Verbosity, v.SamplingType,
		v.SamplingPercentage, document, v.ETag)
	return v, err
}

// GetDiagnostic finds one diagnostic by ARM ID.
func (s *Store) GetDiagnostic(id string) (model.Diagnostic, error) {
	values, err := scanDiagnostics(s.db.Query(`SELECT service_id, scope_id, name, logger_id, always_log,
      log_client_ip, verbosity, sampling_type, sampling_percentage, document_json, etag
      FROM diagnostics WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.Diagnostic{}, err
	}
	if len(values) == 0 {
		return model.Diagnostic{}, ErrNotFound
	}
	return values[0], nil
}

// ListDiagnostics returns diagnostics at exactly one scope in stable ID order.
func (s *Store) ListDiagnostics(scopeID string) ([]model.Diagnostic, error) {
	return scanDiagnostics(s.db.Query(`SELECT service_id, scope_id, name, logger_id, always_log,
      log_client_ip, verbosity, sampling_type, sampling_percentage, document_json, etag
      FROM diagnostics WHERE lower(scope_id)=lower(?) ORDER BY id`, scopeID))
}

// ListServiceDiagnostics returns every diagnostic owned by a service or its API children.
func (s *Store) ListServiceDiagnostics(serviceID string) ([]model.Diagnostic, error) {
	return scanDiagnostics(s.db.Query(`SELECT service_id, scope_id, name, logger_id, always_log,
      log_client_ip, verbosity, sampling_type, sampling_percentage, document_json, etag
      FROM diagnostics WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanDiagnostics(rows *sql.Rows, err error) ([]model.Diagnostic, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Diagnostic, 0)
	for rows.Next() {
		var v model.Diagnostic
		var document string
		if err := rows.Scan(&v.ServiceID, &v.ScopeID, &v.Name, &v.LoggerID, &v.AlwaysLog,
			&v.LogClientIP, &v.Verbosity, &v.SamplingType, &v.SamplingPercentage, &document, &v.ETag); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteDiagnostic removes a diagnostic.
func (s *Store) DeleteDiagnostic(id string) error {
	return deleteScopedResource(s.db, "diagnostics", id)
}

// AddDiagnosticEvent persists one local gateway telemetry event.
func (s *Store) AddDiagnosticEvent(v model.DiagnosticEvent) error {
	_, err := s.db.Exec(`INSERT INTO diagnostic_events
      (id, service_id, api_id, diagnostic_id, correlation_id, method, path, status_code,
       timestamp, duration_nanos, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.ServiceID, v.APIID, v.DiagnosticID, v.CorrelationID, v.Method, v.Path,
		v.StatusCode, v.Timestamp, v.DurationNanos, v.ClientIP)
	return err
}

// ListDiagnosticEvents returns persisted events for a service in insertion-time order.
func (s *Store) ListDiagnosticEvents(serviceID string) ([]model.DiagnosticEvent, error) {
	rows, err := s.db.Query(`SELECT id, service_id, api_id, diagnostic_id, correlation_id, method,
      path, status_code, timestamp, duration_nanos, client_ip FROM diagnostic_events
      WHERE lower(service_id)=lower(?) ORDER BY timestamp, id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.DiagnosticEvent, 0)
	for rows.Next() {
		var v model.DiagnosticEvent
		if err := rows.Scan(&v.ID, &v.ServiceID, &v.APIID, &v.DiagnosticID, &v.CorrelationID,
			&v.Method, &v.Path, &v.StatusCode, &v.Timestamp, &v.DurationNanos, &v.ClientIP); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// RuntimeData returns all resources needed to compile gateway snapshots.
func (s *Store) RuntimeData() ([]model.Service, []model.API, []model.Operation, []model.Product, map[string][]string, []model.Subscription, []model.Policy, error) {
	services, err := s.ListServices()
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	apis, err := scanAPIs(s.db)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	operations, err := scanOperations(s.db)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	products, err := scanProducts(s.db)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	links, err := scanLinks(s.db)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	subscriptions, err := scanSubscriptions(s.db)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, err
	}
	policies, err := scanPolicies(s.db)
	return services, apis, operations, products, links, subscriptions, policies, err
}

func scanAPIs(db *sql.DB) ([]model.API, error) {
	rows, err := db.Query(`SELECT service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag,
	    COALESCE((SELECT revision FROM api_revision_metadata WHERE api_id=apis.id), '1'),
	    COALESCE((SELECT description FROM api_revision_metadata WHERE api_id=apis.id), ''),
	    COALESCE((SELECT is_current FROM api_revision_metadata WHERE api_id=apis.id), 1),
	    COALESCE((SELECT created_at FROM api_revision_metadata WHERE api_id=apis.id), 0),
	    COALESCE((SELECT updated_at FROM api_revision_metadata WHERE api_id=apis.id), 0),
	    COALESCE((SELECT version FROM api_version_metadata WHERE api_id=apis.id), ''),
	    COALESCE((SELECT version_set_id FROM api_version_metadata WHERE api_id=apis.id), ''),
	    COALESCE((SELECT document_json FROM api_documents WHERE api_id=apis.id), '{}')
	    FROM apis ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.API
	for rows.Next() {
		var v model.API
		var protocols, document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Path, &v.ServiceURL, &protocols,
			&v.SubscriptionRequired, &v.ETag, &v.Revision, &v.RevisionDescription, &v.IsCurrent,
			&v.CreatedAt, &v.UpdatedAt, &v.Version, &v.VersionSetID, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(protocols), &v.Protocols)
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanOperations(db *sql.DB) ([]model.Operation, error) {
	rows, err := db.Query(`SELECT api_id, name, display_name, method, url_template, etag,
	    COALESCE((SELECT document_json FROM operation_documents WHERE operation_id=operations.id), '{}')
	    FROM operations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Operation
	for rows.Next() {
		var v model.Operation
		var document string
		if err := rows.Scan(&v.APIID, &v.Name, &v.DisplayName, &v.Method, &v.URLTemplate, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanProducts(db *sql.DB) ([]model.Product, error) {
	rows, err := db.Query(`SELECT service_id, name, display_name, state, approval_required, etag,
	    COALESCE((SELECT document_json FROM product_documents WHERE product_id=products.id), '{}')
	    FROM products ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Product
	for rows.Next() {
		var v model.Product
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.State, &v.ApprovalRequired, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanLinks(db *sql.DB) (map[string][]string, error) {
	rows, err := db.Query(`SELECT product_id, api_id FROM product_apis ORDER BY product_id, api_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := map[string][]string{}
	for rows.Next() {
		var productID, apiID string
		if err := rows.Scan(&productID, &apiID); err != nil {
			return nil, err
		}
		values[productID] = append(values[productID], apiID)
	}
	return values, rows.Err()
}

func scanSubscriptions(db *sql.DB) ([]model.Subscription, error) {
	rows, err := db.Query(`SELECT service_id, name, display_name, scope, state, primary_key, secondary_key, etag,
	    COALESCE((SELECT document_json FROM subscription_documents WHERE subscription_id=subscriptions.id), '{}')
	    FROM subscriptions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Subscription
	for rows.Next() {
		var v model.Subscription
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Scope, &v.State, &v.PrimaryKey, &v.SecondaryKey, &v.ETag, &document); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanPolicies(db *sql.DB) ([]model.Policy, error) {
	rows, err := db.Query(`SELECT scope_id, format, value, etag FROM policies ORDER BY scope_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Policy
	for rows.Next() {
		var v model.Policy
		if err := rows.Scan(&v.ScopeID, &v.Format, &v.Value, &v.ETag); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func deleteScopedResource(db *sql.DB, table, id string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM policies WHERE lower(scope_id)=lower(?) OR lower(scope_id) LIKE lower(?)`, id, id+"/%"); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM resource_tags WHERE lower(resource_id)=lower(?) OR lower(resource_id) LIKE lower(?)`, id, id+"/%"); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM diagnostics WHERE lower(scope_id)=lower(?) OR lower(scope_id) LIKE lower(?)`, id, id+"/%"); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM `+table+` WHERE lower(id)=lower(?)`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func equalID(left, right string) bool { return strings.EqualFold(left, right) }

func splitRevision(name string) (string, string) {
	index := strings.LastIndex(strings.ToLower(name), ";rev=")
	if index < 0 {
		return name, "1"
	}
	return name[:index], name[index+5:]
}
