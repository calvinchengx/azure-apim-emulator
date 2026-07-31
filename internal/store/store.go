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
CREATE TABLE IF NOT EXISTS api_revision_metadata (
  api_id TEXT PRIMARY KEY REFERENCES apis(id) ON DELETE CASCADE,
  revision TEXT NOT NULL, description TEXT NOT NULL, is_current INTEGER NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_version_sets (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, versioning_scheme TEXT NOT NULL,
  version_header_name TEXT NOT NULL, version_query_name TEXT NOT NULL,
  description TEXT NOT NULL, etag TEXT NOT NULL
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
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY, api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, method TEXT NOT NULL,
  url_template TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, state TEXT NOT NULL,
  approval_required INTEGER NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product_apis (
  product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
  api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  PRIMARY KEY (product_id, api_id)
);
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, scope TEXT NOT NULL,
  state TEXT NOT NULL, primary_key TEXT NOT NULL, secondary_key TEXT NOT NULL,
  etag TEXT NOT NULL
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
	if _, err := tx.Exec(`INSERT INTO policies (scope_id, format, value, etag)
	    SELECT ?, format, value, ? FROM policies WHERE lower(scope_id)=lower(?)`, v.ID(), newETag(), sourceID); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetAPI finds one API by ARM ID.
func (s *Store) GetAPI(id string) (model.API, error) {
	var v model.API
	var protocols string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, path, service_url,
	      protocols_json, subscription_required, etag,
	      COALESCE((SELECT revision FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), '1'),
	      COALESCE((SELECT description FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), ''),
	      COALESCE((SELECT is_current FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), 1),
	      COALESCE((SELECT created_at FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), 0),
	      COALESCE((SELECT updated_at FROM api_revision_metadata WHERE lower(api_id)=lower(apis.id)), 0),
	      COALESCE((SELECT version FROM api_version_metadata WHERE lower(api_id)=lower(apis.id)), ''),
	      COALESCE((SELECT version_set_id FROM api_version_metadata WHERE lower(api_id)=lower(apis.id)), '')
	      FROM apis WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Path, &v.ServiceURL,
			&protocols, &v.SubscriptionRequired, &v.ETag, &v.Revision, &v.RevisionDescription,
			&v.IsCurrent, &v.CreatedAt, &v.UpdatedAt, &v.Version, &v.VersionSetID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.API{}, ErrNotFound
	}
	if err != nil {
		return model.API{}, err
	}
	_ = json.Unmarshal([]byte(protocols), &v.Protocols)
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
	err := s.db.QueryRow(`SELECT api_id, name, target_api_id, notes, created_at, updated_at, etag
	    FROM api_releases WHERE lower(id)=lower(?)`, id).
		Scan(&v.APIID, &v.Name, &v.TargetAPIID, &v.Notes, &v.CreatedAt, &v.UpdatedAt, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIRelease{}, ErrNotFound
	}
	return v, err
}

// ListAPIReleases returns releases for an API in stable ID order.
func (s *Store) ListAPIReleases(apiID string) ([]model.APIRelease, error) {
	rows, err := s.db.Query(`SELECT api_id, name, target_api_id, notes, created_at, updated_at, etag
	    FROM api_releases WHERE lower(api_id)=lower(?) ORDER BY id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APIRelease, 0)
	for rows.Next() {
		var v model.APIRelease
		if err := rows.Scan(&v.APIID, &v.Name, &v.TargetAPIID, &v.Notes, &v.CreatedAt, &v.UpdatedAt, &v.ETag); err != nil {
			return nil, err
		}
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
	_, err := s.db.Exec(`INSERT INTO api_version_sets
	    (id, service_id, name, display_name, versioning_scheme, version_header_name, version_query_name, description, etag)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,
	      versioning_scheme=excluded.versioning_scheme, version_header_name=excluded.version_header_name,
	      version_query_name=excluded.version_query_name, description=excluded.description, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.VersioningScheme, v.VersionHeaderName,
		v.VersionQueryName, v.Description, v.ETag)
	return v, err
}

// GetAPIVersionSet finds one version set.
func (s *Store) GetAPIVersionSet(id string) (model.APIVersionSet, error) {
	var v model.APIVersionSet
	err := s.db.QueryRow(`SELECT service_id, name, display_name, versioning_scheme,
	    version_header_name, version_query_name, description, etag FROM api_version_sets WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.VersioningScheme, &v.VersionHeaderName,
			&v.VersionQueryName, &v.Description, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIVersionSet{}, ErrNotFound
	}
	return v, err
}

// ListAPIVersionSets returns version sets for a service in stable ID order.
func (s *Store) ListAPIVersionSets(serviceID string) ([]model.APIVersionSet, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, versioning_scheme,
	    version_header_name, version_query_name, description, etag FROM api_version_sets
	    WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APIVersionSet, 0)
	for rows.Next() {
		var v model.APIVersionSet
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.VersioningScheme,
			&v.VersionHeaderName, &v.VersionQueryName, &v.Description, &v.ETag); err != nil {
			return nil, err
		}
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
	v.ETag = newETag()
	tags, _ := json.Marshal(v.Tags)
	_, err := s.db.Exec(`INSERT INTO named_values
        (id, service_id, name, display_name, value, tags_json, secret, key_vault_secret_id, key_vault_identity_id, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
          display_name=excluded.display_name, value=excluded.value, tags_json=excluded.tags_json,
          secret=excluded.secret, key_vault_secret_id=excluded.key_vault_secret_id,
          key_vault_identity_id=excluded.key_vault_identity_id, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Value, string(tags), v.Secret,
		v.KeyVaultSecretID, v.KeyVaultIdentityID, v.ETag)
	return v, err
}

// GetNamedValue finds one named value.
func (s *Store) GetNamedValue(id string) (model.NamedValue, error) {
	var v model.NamedValue
	var tags string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, value, tags_json, secret,
        key_vault_secret_id, key_vault_identity_id, etag FROM named_values WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Value, &tags, &v.Secret,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.NamedValue{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(tags), &v.Tags)
	}
	return v, err
}

// ListNamedValues returns named values for a service in stable ID order.
func (s *Store) ListNamedValues(serviceID string) ([]model.NamedValue, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, value, tags_json, secret,
        key_vault_secret_id, key_vault_identity_id, etag FROM named_values
        WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.NamedValue, 0)
	for rows.Next() {
		var v model.NamedValue
		var tags string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Value, &tags, &v.Secret,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &v.Tags)
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
	_, err := s.db.Exec(`INSERT INTO operations
    (id, api_id, name, display_name, method, url_template, etag) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, method=excluded.method,
      url_template=excluded.url_template, etag=excluded.etag`, id, v.APIID, v.Name,
		v.DisplayName, strings.ToUpper(v.Method), v.URLTemplate, v.ETag)
	return v, err
}

// GetOperation finds one operation by ARM ID.
func (s *Store) GetOperation(id string) (model.Operation, error) {
	var v model.Operation
	err := s.db.QueryRow(`SELECT api_id, name, display_name, method, url_template, etag
	    FROM operations WHERE lower(id)=lower(?)`, id).
		Scan(&v.APIID, &v.Name, &v.DisplayName, &v.Method, &v.URLTemplate, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Operation{}, ErrNotFound
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
	_, err := s.db.Exec(`INSERT INTO products
    (id, service_id, name, display_name, state, approval_required, etag) VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, state=excluded.state,
      approval_required=excluded.approval_required, etag=excluded.etag`, v.ID(), v.ServiceID,
		v.Name, v.DisplayName, v.State, v.ApprovalRequired, v.ETag)
	return v, err
}

// GetProduct finds one product by ARM ID.
func (s *Store) GetProduct(id string) (model.Product, error) {
	var v model.Product
	err := s.db.QueryRow(`SELECT service_id, name, display_name, state, approval_required, etag
	    FROM products WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.State, &v.ApprovalRequired, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Product{}, ErrNotFound
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
	_, err := s.db.Exec(`INSERT INTO subscriptions
    (id, service_id, name, display_name, scope, state, primary_key, secondary_key, etag)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, scope=excluded.scope,
      state=excluded.state, primary_key=excluded.primary_key, secondary_key=excluded.secondary_key,
      etag=excluded.etag`, v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Scope, v.State,
		v.PrimaryKey, v.SecondaryKey, v.ETag)
	return v, err
}

// GetSubscription finds one subscription by ARM ID.
func (s *Store) GetSubscription(id string) (model.Subscription, error) {
	var v model.Subscription
	err := s.db.QueryRow(`SELECT service_id, name, display_name, scope, state, primary_key, secondary_key, etag
	    FROM subscriptions WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Scope, &v.State, &v.PrimaryKey, &v.SecondaryKey, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Subscription{}, ErrNotFound
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
	    COALESCE((SELECT version_set_id FROM api_version_metadata WHERE api_id=apis.id), '')
	    FROM apis ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.API
	for rows.Next() {
		var v model.API
		var protocols string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Path, &v.ServiceURL, &protocols,
			&v.SubscriptionRequired, &v.ETag, &v.Revision, &v.RevisionDescription, &v.IsCurrent,
			&v.CreatedAt, &v.UpdatedAt, &v.Version, &v.VersionSetID); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(protocols), &v.Protocols)
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanOperations(db *sql.DB) ([]model.Operation, error) {
	rows, err := db.Query(`SELECT api_id, name, display_name, method, url_template, etag FROM operations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Operation
	for rows.Next() {
		var v model.Operation
		if err := rows.Scan(&v.APIID, &v.Name, &v.DisplayName, &v.Method, &v.URLTemplate, &v.ETag); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func scanProducts(db *sql.DB) ([]model.Product, error) {
	rows, err := db.Query(`SELECT service_id, name, display_name, state, approval_required, etag FROM products ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Product
	for rows.Next() {
		var v model.Product
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.State, &v.ApprovalRequired, &v.ETag); err != nil {
			return nil, err
		}
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
	rows, err := db.Query(`SELECT service_id, name, display_name, scope, state, primary_key, secondary_key, etag FROM subscriptions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Subscription
	for rows.Next() {
		var v model.Subscription
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Scope, &v.State, &v.PrimaryKey, &v.SecondaryKey, &v.ETag); err != nil {
			return nil, err
		}
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
