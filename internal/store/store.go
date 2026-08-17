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
	"github.com/calvinchengx/azure-apim-emulator/internal/rbac"
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
	if err := s.adoptScopes(); err != nil {
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
-- A scope is the parent of every resource: the service itself, or a workspace
-- inside it. Resource tables reference this rather than services(id), because a
-- workspace-scoped API's parent is the workspace and the two must be
-- indistinguishable to every family that does not care which it is.
--
-- service_id is the owning service for BOTH kinds, so deleting a service
-- cascades to its own scope and to each of its workspaces', and from there to
-- every resource in any of them.
CREATE TABLE IF NOT EXISTS scopes (
  id TEXT PRIMARY KEY,
  service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS resource_documents (
  id TEXT PRIMARY KEY REFERENCES services(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apis (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, url TEXT NOT NULL,
  protocol TEXT NOT NULL, resource_id TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, subject TEXT NOT NULL, thumbprint TEXT NOT NULL, expiration INTEGER NOT NULL,
  data BLOB NOT NULL, password TEXT NOT NULL, key_vault_secret_id TEXT NOT NULL,
  key_vault_identity_id TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificate_documents (
  certificate_id TEXT PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
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
CREATE TABLE IF NOT EXISTS api_schema_documents (
  schema_id TEXT PRIMARY KEY REFERENCES api_schemas(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
-- Role assignments are NOT scoped to a service: one can be made at a
-- subscription or resource group, above any APIM resource. So this table has no
-- foreign key to scopes, and cleanup is by scope prefix rather than cascade.
CREATE TABLE IF NOT EXISTS role_assignments (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, name TEXT NOT NULL,
  principal_id TEXT NOT NULL, principal_type TEXT NOT NULL,
  role_definition_id TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY REFERENCES scopes(id) ON DELETE CASCADE,
  service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, description TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_resolvers (
  id TEXT PRIMARY KEY, api_id TEXT NOT NULL REFERENCES apis(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, description TEXT NOT NULL,
  type TEXT NOT NULL, field TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_providers (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, identity_provider TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorizations (
  id TEXT PRIMARY KEY, provider_id TEXT NOT NULL REFERENCES authorization_providers(id) ON DELETE CASCADE,
  name TEXT NOT NULL, authorization_type TEXT NOT NULL, oauth2_grant_type TEXT NOT NULL,
  status TEXT NOT NULL, error_message TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_access_policies (
  id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL REFERENCES authorizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL, tenant_id TEXT NOT NULL, object_id TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
-- Self-hosted gateways parent to services(id), NOT scopes(id), and that is
-- deliberate: Azure has no service/{svc}/workspaces/{ws}/gateways. A workspace
-- gets a gateway through the separate top-level Microsoft.ApiManagement/gateways
-- resource, so pointing this at scopes(id) would make the emulator accept a URL
-- Azure answers 404 to.
CREATE TABLE IF NOT EXISTS gateways (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, location_name TEXT NOT NULL, description TEXT NOT NULL,
  primary_key TEXT NOT NULL, secondary_key TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_apis (
  gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  api_id TEXT NOT NULL,
  PRIMARY KEY (gateway_id, api_id)
);
CREATE TABLE IF NOT EXISTS gateway_hostname_configurations (
  id TEXT PRIMARY KEY, gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  name TEXT NOT NULL, hostname TEXT NOT NULL, certificate_id TEXT NOT NULL,
  negotiate_client_certificate INTEGER NOT NULL, tls10_enabled INTEGER NOT NULL,
  tls11_enabled INTEGER NOT NULL, http2_enabled INTEGER NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gateway_certificate_authorities (
  id TEXT PRIMARY KEY, gateway_id TEXT NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
  name TEXT NOT NULL, is_trusted INTEGER NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
-- Private endpoint connections parent to services(id), not scopes(id): Azure
-- has no workspace-scoped private endpoint, and the family is refused under a
-- workspace by serviceOnlyFamilies.
CREATE TABLE IF NOT EXISTS private_endpoint_connections (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, status TEXT NOT NULL, description TEXT NOT NULL,
  actions_required TEXT NOT NULL, endpoint_id TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tags (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, description TEXT NOT NULL, type TEXT NOT NULL,
  external_id TEXT NOT NULL, built_in INTEGER NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_documents (
  group_id TEXT PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, description TEXT NOT NULL, format TEXT NOT NULL, value TEXT NOT NULL,
  provisioning_state TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_fragment_documents (
  fragment_id TEXT PRIMARY KEY REFERENCES policy_fragments(id) ON DELETE CASCADE,
  document_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documentations (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_servers (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, description TEXT NOT NULL,
  authorization_endpoint TEXT NOT NULL, client_registration_endpoint TEXT NOT NULL,
  client_id TEXT NOT NULL, client_secret TEXT NOT NULL, token_endpoint TEXT NOT NULL,
  default_scope TEXT NOT NULL, resource_owner_username TEXT NOT NULL,
  resource_owner_password TEXT NOT NULL, support_state INTEGER NOT NULL,
  grant_types_json TEXT NOT NULL, document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS openid_connect_providers (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, description TEXT NOT NULL,
  metadata_endpoint TEXT NOT NULL, client_id TEXT NOT NULL, client_secret TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity_providers (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, client_id TEXT NOT NULL, client_secret TEXT NOT NULL,
  authority TEXT NOT NULL, signin_tenant TEXT NOT NULL, signup_policy_name TEXT NOT NULL,
  signin_policy_name TEXT NOT NULL, profile_editing_policy_name TEXT NOT NULL,
  password_reset_policy_name TEXT NOT NULL, allowed_tenants_json TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS caches (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, description TEXT NOT NULL, connection_string TEXT NOT NULL,
  use_from_location TEXT NOT NULL, resource_id TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS loggers (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  name TEXT NOT NULL, logger_type TEXT NOT NULL, description TEXT NOT NULL,
  is_buffered INTEGER NOT NULL, resource_id TEXT NOT NULL, credentials_json TEXT NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diagnostics (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  scope_id TEXT NOT NULL, name TEXT NOT NULL, logger_id TEXT NOT NULL,
  always_log TEXT NOT NULL, log_client_ip INTEGER NOT NULL, verbosity TEXT NOT NULL,
  sampling_type TEXT NOT NULL, sampling_percentage REAL NOT NULL,
  document_json TEXT NOT NULL, etag TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS diagnostic_events (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
  api_id TEXT NOT NULL, diagnostic_id TEXT NOT NULL, correlation_id TEXT NOT NULL,
  method TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL,
  timestamp INTEGER NOT NULL, duration_nanos INTEGER NOT NULL, client_ip TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
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
	_, _ = s.db.Exec(`ALTER TABLE diagnostic_events ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'`)
	_, _ = s.db.Exec(`ALTER TABLE named_values ADD COLUMN key_vault_status_code TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE named_values ADD COLUMN key_vault_status_message TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE named_values ADD COLUMN key_vault_status_time INTEGER NOT NULL DEFAULT 0`)
	_, _ = s.db.Exec(`ALTER TABLE certificates ADD COLUMN key_vault_status_code TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE certificates ADD COLUMN key_vault_status_message TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE certificates ADD COLUMN key_vault_status_time INTEGER NOT NULL DEFAULT 0`)
	// Link resources are a second PROJECTION of these associations, not a
	// second store, so the name Azure lets a client give a link lives on the
	// association itself. A separate links table would let
	// `products/{id}/apis/{apiId}` and `products/{id}/apiLinks/{name}` disagree
	// about whether the same API is in the same product.
	_, _ = s.db.Exec(`ALTER TABLE product_apis ADD COLUMN link_name TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE product_groups ADD COLUMN link_name TEXT NOT NULL DEFAULT ''`)
	_, _ = s.db.Exec(`ALTER TABLE resource_tags ADD COLUMN link_name TEXT NOT NULL DEFAULT ''`)
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

func unixTime(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func timeFromUnix(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

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
	// A service is its own scope. Registering it here is what lets every
	// resource table reference scopes(id) uniformly, whether its parent is a
	// service or a workspace.
	if _, err := tx.Exec(`INSERT INTO scopes (id, service_id) VALUES (?, ?) ON CONFLICT(id) DO NOTHING`, v.ID(), v.ID()); err != nil {
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
		armDocument, err := json.Marshal(schema.ARMDocument)
		if err != nil {
			return v, err
		}
		schema.APIID, schema.Name, schema.ETag = v.ID(), "openapi", newETag()
		if _, err := tx.Exec(`INSERT INTO api_schemas (id, api_id, name, content_type, document_json, etag)
	          VALUES (?, ?, ?, ?, ?, ?)`, schema.ID(), schema.APIID, schema.Name, schema.ContentType, document, schema.ETag); err != nil {
			return v, err
		}
		if _, err := tx.Exec(`INSERT INTO api_schema_documents (schema_id, document_json) VALUES (?, ?)`, schema.ID(), armDocument); err != nil {
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
	if _, err := tx.Exec(`INSERT INTO api_schema_documents (schema_id, document_json)
		    SELECT ? || substr(schema_id, length(?) + 1), document_json
		    FROM api_schema_documents WHERE lower(schema_id) LIKE lower(?)`,
		v.ID(), sourceID, sourceID+"/schemas/%"); err != nil {
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
        (id, service_id, name, display_name, value, tags_json, secret, key_vault_secret_id, key_vault_identity_id,
         key_vault_status_code, key_vault_status_message, key_vault_status_time, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET
          display_name=excluded.display_name, value=excluded.value, tags_json=excluded.tags_json,
          secret=excluded.secret, key_vault_secret_id=excluded.key_vault_secret_id,
          key_vault_identity_id=excluded.key_vault_identity_id, key_vault_status_code=excluded.key_vault_status_code,
          key_vault_status_message=excluded.key_vault_status_message, key_vault_status_time=excluded.key_vault_status_time,
          etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Value, string(tags), v.Secret,
		v.KeyVaultSecretID, v.KeyVaultIdentityID, v.KeyVaultStatusCode, v.KeyVaultStatusMessage, unixTime(v.KeyVaultStatusTime), v.ETag)
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
	var statusTime int64
	err := s.db.QueryRow(`SELECT service_id, name, display_name, value, tags_json, secret,
		key_vault_secret_id, key_vault_identity_id, key_vault_status_code, key_vault_status_message, key_vault_status_time, etag,
		COALESCE((SELECT document_json FROM named_value_documents WHERE lower(named_value_id)=lower(named_values.id)), '{}')
		FROM named_values WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Value, &tags, &v.Secret,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.KeyVaultStatusCode, &v.KeyVaultStatusMessage, &statusTime, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.NamedValue{}, ErrNotFound
	}
	if err == nil {
		v.KeyVaultStatusTime = timeFromUnix(statusTime)
		_ = json.Unmarshal([]byte(tags), &v.Tags)
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListNamedValues returns named values for a service in stable ID order.
func (s *Store) ListNamedValues(serviceID string) ([]model.NamedValue, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, value, tags_json, secret,
		key_vault_secret_id, key_vault_identity_id, key_vault_status_code, key_vault_status_message, key_vault_status_time, etag,
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
		var statusTime int64
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Value, &tags, &v.Secret,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.KeyVaultStatusCode, &v.KeyVaultStatusMessage, &statusTime, &v.ETag, &document); err != nil {
			return nil, err
		}
		v.KeyVaultStatusTime = timeFromUnix(statusTime)
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
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO backends
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
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	armDocument, err := json.Marshal(v.ARMDocument)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO api_schemas (id, api_id, name, content_type, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET content_type=excluded.content_type,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.APIID, v.Name, v.ContentType, string(document), v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO api_schema_documents (schema_id, document_json) VALUES (?, ?)
	    ON CONFLICT(schema_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), armDocument); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetAPISchema finds one API schema.
func (s *Store) GetAPISchema(id string) (model.APISchema, error) {
	var v model.APISchema
	var document, armDocument string
	err := s.db.QueryRow(`SELECT api_id, name, content_type, document_json, etag,
		COALESCE((SELECT document_json FROM api_schema_documents WHERE lower(schema_id)=lower(api_schemas.id)), '{}')
	        FROM api_schemas WHERE lower(id)=lower(?)`, id).Scan(&v.APIID, &v.Name, &v.ContentType, &document, &v.ETag, &armDocument)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APISchema{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
		_ = json.Unmarshal([]byte(armDocument), &v.ARMDocument)
	}
	return v, err
}

// ListAPISchemas returns schemas for an API in stable ID order.
func (s *Store) ListAPISchemas(apiID string) ([]model.APISchema, error) {
	rows, err := s.db.Query(`SELECT api_id, name, content_type, document_json, etag,
		COALESCE((SELECT document_json FROM api_schema_documents WHERE lower(schema_id)=lower(api_schemas.id)), '{}')
        FROM api_schemas WHERE lower(api_id)=lower(?) ORDER BY id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APISchema, 0)
	for rows.Next() {
		var v model.APISchema
		var document, armDocument string
		if err := rows.Scan(&v.APIID, &v.Name, &v.ContentType, &document, &v.ETag, &armDocument); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		_ = json.Unmarshal([]byte(armDocument), &v.ARMDocument)
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

// ListTagsByScope returns tags associated with resources in one APIM scope.
func (s *Store) ListTagsByScope(serviceID, scope string) ([]model.Tag, error) {
	scope = strings.ToLower(scope)
	resource := ""
	where := ""
	switch strings.ToLower(scope) {
	case "apis":
		where = "lower(resource_tags.resource_id) LIKE lower(?) AND lower(resource_tags.resource_id) NOT LIKE lower(?)"
		resource = serviceID + "/apis/%"
	case "operations":
		where = "lower(resource_tags.resource_id) LIKE lower(?)"
		resource = serviceID + "/apis/%/operations/%"
	case "products":
		where = "lower(resource_tags.resource_id) LIKE lower(?)"
		resource = serviceID + "/products/%"
	default:
		return nil, fmt.Errorf("unsupported tag scope %q", scope)
	}
	args := []any{serviceID, resource}
	if scope == "apis" {
		args = append(args, serviceID+"/apis/%/operations/%")
	}
	return scanTags(s.db.Query(`SELECT DISTINCT tags.service_id, tags.name, tags.display_name, tags.etag,
	    COALESCE((SELECT document_json FROM tag_documents WHERE lower(tag_id)=lower(tags.id)), '{}')
	    FROM tags JOIN resource_tags ON lower(resource_tags.tag_id)=lower(tags.id)
	    WHERE lower(tags.service_id)=lower(?) AND `+where+` ORDER BY tags.id`, args...))
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
	sanitizeCertificateDocument(v.Document)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	if v.Data == nil {
		v.Data = []byte{}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO certificates
        (id, service_id, name, subject, thumbprint, expiration, data, password, key_vault_secret_id, key_vault_identity_id,
         key_vault_status_code, key_vault_status_message, key_vault_status_time, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET subject=excluded.subject,
          thumbprint=excluded.thumbprint, expiration=excluded.expiration, data=excluded.data,
          password=excluded.password, key_vault_secret_id=excluded.key_vault_secret_id,
          key_vault_identity_id=excluded.key_vault_identity_id, key_vault_status_code=excluded.key_vault_status_code,
          key_vault_status_message=excluded.key_vault_status_message, key_vault_status_time=excluded.key_vault_status_time,
          etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.Subject, v.Thumbprint, v.Expiration.Unix(), v.Data, v.Password,
		v.KeyVaultSecretID, v.KeyVaultIdentityID, v.KeyVaultStatusCode, v.KeyVaultStatusMessage, unixTime(v.KeyVaultStatusTime), v.ETag)
	if err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO certificate_documents (certificate_id, document_json) VALUES (?, ?)
	    ON CONFLICT(certificate_id) DO UPDATE SET document_json=excluded.document_json`, v.ID(), document); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

func sanitizeCertificateDocument(document map[string]any) {
	delete(document, "data")
	delete(document, "password")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "data")
	delete(properties, "password")
	delete(properties, "subject")
	delete(properties, "thumbprint")
	delete(properties, "expirationDate")
}

// GetCertificate finds one certificate.
func (s *Store) GetCertificate(id string) (model.Certificate, error) {
	var v model.Certificate
	var expiration int64
	var document string
	var statusTime int64
	err := s.db.QueryRow(`SELECT service_id, name, subject, thumbprint, expiration, data, password,
		key_vault_secret_id, key_vault_identity_id, key_vault_status_code, key_vault_status_message, key_vault_status_time, etag,
		COALESCE((SELECT document_json FROM certificate_documents WHERE lower(certificate_id)=lower(certificates.id)), '{}')
		FROM certificates WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.Subject, &v.Thumbprint, &expiration, &v.Data, &v.Password,
			&v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.KeyVaultStatusCode, &v.KeyVaultStatusMessage, &statusTime, &v.ETag, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Certificate{}, ErrNotFound
	}
	if err == nil {
		if expiration != 0 {
			v.Expiration = time.Unix(expiration, 0).UTC()
		}
		v.KeyVaultStatusTime = timeFromUnix(statusTime)
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListCertificates returns certificates for a service in stable ID order.
func (s *Store) ListCertificates(serviceID string) ([]model.Certificate, error) {
	rows, err := s.db.Query(`SELECT service_id, name, subject, thumbprint, expiration, data, password,
		key_vault_secret_id, key_vault_identity_id, key_vault_status_code, key_vault_status_message, key_vault_status_time, etag,
		COALESCE((SELECT document_json FROM certificate_documents WHERE lower(certificate_id)=lower(certificates.id)), '{}')
		FROM certificates
        WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Certificate, 0)
	for rows.Next() {
		var v model.Certificate
		var expiration int64
		var document string
		var statusTime int64
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Subject, &v.Thumbprint, &expiration, &v.Data,
			&v.Password, &v.KeyVaultSecretID, &v.KeyVaultIdentityID, &v.KeyVaultStatusCode, &v.KeyVaultStatusMessage, &statusTime, &v.ETag, &document); err != nil {
			return nil, err
		}
		if expiration != 0 {
			v.Expiration = time.Unix(expiration, 0).UTC()
		}
		v.KeyVaultStatusTime = timeFromUnix(statusTime)
		_ = json.Unmarshal([]byte(document), &v.Document)
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

// UpsertDocumentation creates or replaces a documentation article while preserving its ARM document.
func (s *Store) UpsertDocumentation(v model.Documentation) (model.Documentation, error) {
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO documentations (id, service_id, name, title, content, document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET title=excluded.title, content=excluded.content,
        document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.Title, v.Content, document, v.ETag)
	return v, err
}

// GetDocumentation finds one documentation article by ARM ID.
func (s *Store) GetDocumentation(id string) (model.Documentation, error) {
	values, err := scanDocumentations(s.db.Query(`SELECT service_id, name, title, content, document_json, etag
      FROM documentations WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.Documentation{}, err
	}
	if len(values) == 0 {
		return model.Documentation{}, ErrNotFound
	}
	return values[0], nil
}

// ListDocumentations returns service documentation articles in stable ID order.
func (s *Store) ListDocumentations(serviceID string) ([]model.Documentation, error) {
	return scanDocumentations(s.db.Query(`SELECT service_id, name, title, content, document_json, etag
      FROM documentations WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanDocumentations(rows *sql.Rows, err error) ([]model.Documentation, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Documentation, 0)
	for rows.Next() {
		var v model.Documentation
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Title, &v.Content, &document, &v.ETag); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteDocumentation removes one documentation article.
func (s *Store) DeleteDocumentation(id string) error {
	return deleteScopedResource(s.db, "documentations", id)
}

// UpsertAuthorizationServer creates or replaces an OAuth authorization server while preserving its ARM document.
func (s *Store) UpsertAuthorizationServer(v model.AuthorizationServer) (model.AuthorizationServer, error) {
	sanitizeAuthorizationServerDocument(v.Document)
	v.ETag = newETag()
	if v.GrantTypes == nil {
		v.GrantTypes = []string{}
	}
	grants, _ := json.Marshal(v.GrantTypes)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	supportState := 0
	if v.SupportState {
		supportState = 1
	}
	_, err = s.db.Exec(`INSERT INTO authorization_servers
      (id, service_id, name, display_name, description, authorization_endpoint, client_registration_endpoint,
       client_id, client_secret, token_endpoint, default_scope, resource_owner_username, resource_owner_password,
       support_state, grant_types_json, document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, description=excluded.description,
        authorization_endpoint=excluded.authorization_endpoint, client_registration_endpoint=excluded.client_registration_endpoint,
        client_id=excluded.client_id, client_secret=excluded.client_secret, token_endpoint=excluded.token_endpoint,
        default_scope=excluded.default_scope, resource_owner_username=excluded.resource_owner_username,
        resource_owner_password=excluded.resource_owner_password, support_state=excluded.support_state,
        grant_types_json=excluded.grant_types_json, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Description, v.AuthorizationEndpoint, v.ClientRegistrationEndpoint,
		v.ClientID, v.ClientSecret, v.TokenEndpoint, v.DefaultScope, v.ResourceOwnerUsername, v.ResourceOwnerPassword,
		supportState, grants, document, v.ETag)
	return v, err
}

func sanitizeAuthorizationServerDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

// GetAuthorizationServer finds one authorization server by ARM ID.
func (s *Store) GetAuthorizationServer(id string) (model.AuthorizationServer, error) {
	values, err := scanAuthorizationServers(s.db.Query(`SELECT service_id, name, display_name, description,
      authorization_endpoint, client_registration_endpoint, client_id, client_secret, token_endpoint,
      default_scope, resource_owner_username, resource_owner_password, support_state, grant_types_json, document_json, etag
      FROM authorization_servers WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.AuthorizationServer{}, err
	}
	if len(values) == 0 {
		return model.AuthorizationServer{}, ErrNotFound
	}
	return values[0], nil
}

// ListAuthorizationServers returns service authorization servers in stable ID order.
func (s *Store) ListAuthorizationServers(serviceID string) ([]model.AuthorizationServer, error) {
	return scanAuthorizationServers(s.db.Query(`SELECT service_id, name, display_name, description,
      authorization_endpoint, client_registration_endpoint, client_id, client_secret, token_endpoint,
      default_scope, resource_owner_username, resource_owner_password, support_state, grant_types_json, document_json, etag
      FROM authorization_servers WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanAuthorizationServers(rows *sql.Rows, err error) ([]model.AuthorizationServer, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.AuthorizationServer, 0)
	for rows.Next() {
		var v model.AuthorizationServer
		var supportState int
		var grants, document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Description, &v.AuthorizationEndpoint,
			&v.ClientRegistrationEndpoint, &v.ClientID, &v.ClientSecret, &v.TokenEndpoint, &v.DefaultScope,
			&v.ResourceOwnerUsername, &v.ResourceOwnerPassword, &supportState, &grants, &document, &v.ETag); err != nil {
			return nil, err
		}
		v.SupportState = supportState == 1
		if err := json.Unmarshal([]byte(grants), &v.GrantTypes); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAuthorizationServer removes one authorization server.
func (s *Store) DeleteAuthorizationServer(id string) error {
	return deleteScopedResource(s.db, "authorization_servers", id)
}

// UpsertOpenIDConnectProvider creates or replaces an OpenID Connect provider while preserving its ARM document.
func (s *Store) UpsertOpenIDConnectProvider(v model.OpenIDConnectProvider) (model.OpenIDConnectProvider, error) {
	sanitizeOpenIDConnectProviderDocument(v.Document)
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO openid_connect_providers
      (id, service_id, name, display_name, description, metadata_endpoint, client_id, client_secret, document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, description=excluded.description,
        metadata_endpoint=excluded.metadata_endpoint, client_id=excluded.client_id,
        client_secret=excluded.client_secret, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Description, v.MetadataEndpoint, v.ClientID, v.ClientSecret, document, v.ETag)
	return v, err
}

func sanitizeOpenIDConnectProviderDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

// GetOpenIDConnectProvider finds one OpenID Connect provider by ARM ID.
func (s *Store) GetOpenIDConnectProvider(id string) (model.OpenIDConnectProvider, error) {
	values, err := scanOpenIDConnectProviders(s.db.Query(`SELECT service_id, name, display_name, description,
      metadata_endpoint, client_id, client_secret, document_json, etag
      FROM openid_connect_providers WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.OpenIDConnectProvider{}, err
	}
	if len(values) == 0 {
		return model.OpenIDConnectProvider{}, ErrNotFound
	}
	return values[0], nil
}

// ListOpenIDConnectProviders returns service OpenID Connect providers in stable ID order.
func (s *Store) ListOpenIDConnectProviders(serviceID string) ([]model.OpenIDConnectProvider, error) {
	return scanOpenIDConnectProviders(s.db.Query(`SELECT service_id, name, display_name, description,
      metadata_endpoint, client_id, client_secret, document_json, etag
      FROM openid_connect_providers WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanOpenIDConnectProviders(rows *sql.Rows, err error) ([]model.OpenIDConnectProvider, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.OpenIDConnectProvider, 0)
	for rows.Next() {
		var v model.OpenIDConnectProvider
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Description, &v.MetadataEndpoint,
			&v.ClientID, &v.ClientSecret, &document, &v.ETag); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteOpenIDConnectProvider removes one OpenID Connect provider.
func (s *Store) DeleteOpenIDConnectProvider(id string) error {
	return deleteScopedResource(s.db, "openid_connect_providers", id)
}

// UpsertIdentityProvider creates or replaces an identity provider while preserving its ARM document.
func (s *Store) UpsertIdentityProvider(v model.IdentityProvider) (model.IdentityProvider, error) {
	sanitizeIdentityProviderDocument(v.Document)
	v.ETag = newETag()
	if v.AllowedTenants == nil {
		v.AllowedTenants = []string{}
	}
	tenants, _ := json.Marshal(v.AllowedTenants)
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO identity_providers
      (id, service_id, name, client_id, client_secret, authority, signin_tenant, signup_policy_name,
       signin_policy_name, profile_editing_policy_name, password_reset_policy_name, allowed_tenants_json,
       document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET client_id=excluded.client_id, client_secret=excluded.client_secret,
        authority=excluded.authority, signin_tenant=excluded.signin_tenant,
        signup_policy_name=excluded.signup_policy_name, signin_policy_name=excluded.signin_policy_name,
        profile_editing_policy_name=excluded.profile_editing_policy_name,
        password_reset_policy_name=excluded.password_reset_policy_name,
        allowed_tenants_json=excluded.allowed_tenants_json, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.ClientID, v.ClientSecret, v.Authority, v.SigninTenant,
		v.SignupPolicyName, v.SigninPolicyName, v.ProfileEditingPolicyName, v.PasswordResetPolicyName,
		tenants, document, v.ETag)
	return v, err
}

func sanitizeIdentityProviderDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "clientSecret")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "clientSecret")
}

// GetIdentityProvider finds one identity provider by ARM ID.
func (s *Store) GetIdentityProvider(id string) (model.IdentityProvider, error) {
	values, err := scanIdentityProviders(s.db.Query(`SELECT service_id, name, client_id, client_secret, authority,
      signin_tenant, signup_policy_name, signin_policy_name, profile_editing_policy_name,
      password_reset_policy_name, allowed_tenants_json, document_json, etag
      FROM identity_providers WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.IdentityProvider{}, err
	}
	if len(values) == 0 {
		return model.IdentityProvider{}, ErrNotFound
	}
	return values[0], nil
}

// ListIdentityProviders returns service identity providers in stable ID order.
func (s *Store) ListIdentityProviders(serviceID string) ([]model.IdentityProvider, error) {
	return scanIdentityProviders(s.db.Query(`SELECT service_id, name, client_id, client_secret, authority,
      signin_tenant, signup_policy_name, signin_policy_name, profile_editing_policy_name,
      password_reset_policy_name, allowed_tenants_json, document_json, etag
      FROM identity_providers WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanIdentityProviders(rows *sql.Rows, err error) ([]model.IdentityProvider, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.IdentityProvider, 0)
	for rows.Next() {
		var v model.IdentityProvider
		var tenants, document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.ClientID, &v.ClientSecret, &v.Authority,
			&v.SigninTenant, &v.SignupPolicyName, &v.SigninPolicyName, &v.ProfileEditingPolicyName,
			&v.PasswordResetPolicyName, &tenants, &document, &v.ETag); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(tenants), &v.AllowedTenants); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteIdentityProvider removes one identity provider.
func (s *Store) DeleteIdentityProvider(id string) error {
	return deleteScopedResource(s.db, "identity_providers", id)
}

// UpsertCache creates or replaces an external cache while preserving its ARM document.
func (s *Store) UpsertCache(v model.Cache) (model.Cache, error) {
	sanitizeCacheDocument(v.Document)
	v.ETag = newETag()
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	_, err = s.db.Exec(`INSERT INTO caches
      (id, service_id, name, description, connection_string, use_from_location, resource_id, document_json, etag)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET description=excluded.description,
        connection_string=excluded.connection_string, use_from_location=excluded.use_from_location,
        resource_id=excluded.resource_id, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.Description, v.ConnectionString, v.UseFromLocation,
		v.ResourceID, document, v.ETag)
	return v, err
}

func sanitizeCacheDocument(document map[string]any) {
	if document == nil {
		return
	}
	delete(document, "connectionString")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "connectionString")
}

// GetCache finds one cache by ARM ID.
func (s *Store) GetCache(id string) (model.Cache, error) {
	values, err := scanCaches(s.db.Query(`SELECT service_id, name, description, connection_string,
      use_from_location, resource_id, document_json, etag FROM caches WHERE lower(id)=lower(?)`, id))
	if err != nil {
		return model.Cache{}, err
	}
	if len(values) == 0 {
		return model.Cache{}, ErrNotFound
	}
	return values[0], nil
}

// ListCaches returns service caches in stable ID order.
func (s *Store) ListCaches(serviceID string) ([]model.Cache, error) {
	return scanCaches(s.db.Query(`SELECT service_id, name, description, connection_string,
      use_from_location, resource_id, document_json, etag FROM caches
      WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID))
}

func scanCaches(rows *sql.Rows, err error) ([]model.Cache, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Cache, 0)
	for rows.Next() {
		var v model.Cache
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.Description, &v.ConnectionString,
			&v.UseFromLocation, &v.ResourceID, &document, &v.ETag); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(document), &v.Document); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteCache removes one cache.
func (s *Store) DeleteCache(id string) error {
	return deleteScopedResource(s.db, "caches", id)
}

// UpsertLogger creates or replaces a service logger while preserving its ARM document.
func (s *Store) UpsertLogger(v model.Logger) (model.Logger, error) {
	sanitizeLoggerDocument(v.Document)
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

func sanitizeLoggerDocument(document map[string]any) {
	delete(document, "credentials")
	properties, _ := document["properties"].(map[string]any)
	delete(properties, "credentials")
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
	metadata, err := json.Marshal(v.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO diagnostic_events
      (id, service_id, api_id, diagnostic_id, correlation_id, method, path, status_code,
       timestamp, duration_nanos, client_ip, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.ServiceID, v.APIID, v.DiagnosticID, v.CorrelationID, v.Method, v.Path,
		v.StatusCode, v.Timestamp, v.DurationNanos, v.ClientIP, string(metadata))
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "metadata_json") {
		_, err = s.db.Exec(`INSERT INTO diagnostic_events
      (id, service_id, api_id, diagnostic_id, correlation_id, method, path, status_code,
       timestamp, duration_nanos, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			v.ID, v.ServiceID, v.APIID, v.DiagnosticID, v.CorrelationID, v.Method, v.Path,
			v.StatusCode, v.Timestamp, v.DurationNanos, v.ClientIP)
	}
	return err
}

// ListDiagnosticEvents returns persisted events for a service in insertion-time order.
func (s *Store) ListDiagnosticEvents(serviceID string) ([]model.DiagnosticEvent, error) {
	rows, err := s.db.Query(`SELECT id, service_id, api_id, diagnostic_id, correlation_id, method,
      path, status_code, timestamp, duration_nanos, client_ip, metadata_json FROM diagnostic_events
      WHERE lower(service_id)=lower(?) ORDER BY timestamp, id`, serviceID)
	legacy := false
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "metadata_json") {
		legacy = true
		rows, err = s.db.Query(`SELECT id, service_id, api_id, diagnostic_id, correlation_id, method,
      path, status_code, timestamp, duration_nanos, client_ip FROM diagnostic_events
      WHERE lower(service_id)=lower(?) ORDER BY timestamp, id`, serviceID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.DiagnosticEvent, 0)
	for rows.Next() {
		var v model.DiagnosticEvent
		var metadata string
		scanValues := []any{&v.ID, &v.ServiceID, &v.APIID, &v.DiagnosticID, &v.CorrelationID,
			&v.Method, &v.Path, &v.StatusCode, &v.Timestamp, &v.DurationNanos, &v.ClientIP}
		if !legacy {
			scanValues = append(scanValues, &metadata)
		}
		if err := rows.Scan(scanValues...); err != nil {
			return nil, err
		}
		if metadata != "" {
			_ = json.Unmarshal([]byte(metadata), &v.Metadata)
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

// UpsertAPIResolver creates or replaces a GraphQL resolver.
func (s *Store) UpsertAPIResolver(v model.APIResolver) (model.APIResolver, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO api_resolvers (id, api_id, name, display_name, description, type, field, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,
          description=excluded.description, type=excluded.type, field=excluded.field,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.APIID, v.Name, v.DisplayName, v.Description, v.Type, v.Field, string(document), v.ETag)
	return v, err
}

// GetAPIResolver finds one GraphQL resolver.
func (s *Store) GetAPIResolver(id string) (model.APIResolver, error) {
	var v model.APIResolver
	var document string
	err := s.db.QueryRow(`SELECT api_id, name, display_name, description, type, field, document_json, etag
	        FROM api_resolvers WHERE lower(id)=lower(?)`, id).
		Scan(&v.APIID, &v.Name, &v.DisplayName, &v.Description, &v.Type, &v.Field, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIResolver{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAPIResolvers returns an API's resolvers in stable ID order.
func (s *Store) ListAPIResolvers(apiID string) ([]model.APIResolver, error) {
	rows, err := s.db.Query(`SELECT api_id, name, display_name, description, type, field, document_json, etag
        FROM api_resolvers WHERE lower(api_id)=lower(?) ORDER BY id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.APIResolver, 0)
	for rows.Next() {
		var v model.APIResolver
		var document string
		if err := rows.Scan(&v.APIID, &v.Name, &v.DisplayName, &v.Description, &v.Type, &v.Field, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAPIResolver removes a GraphQL resolver.
func (s *Store) DeleteAPIResolver(id string) error {
	return deleteScopedResource(s.db, "api_resolvers", id)
}

// UpsertWorkspace creates or replaces a workspace.
func (s *Store) UpsertWorkspace(v model.Workspace) (model.Workspace, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	tx, err := s.db.Begin()
	if err != nil {
		return v, err
	}
	defer tx.Rollback()
	// The scope comes first: the workspace row hangs off it, and so does every
	// resource parented to the workspace, so deleting the scope is what takes
	// the whole subtree.
	if _, err := tx.Exec(`INSERT INTO scopes (id, service_id) VALUES (?, ?) ON CONFLICT(id) DO NOTHING`, v.ID(), v.ServiceID); err != nil {
		return v, err
	}
	if _, err := tx.Exec(`INSERT INTO workspaces (id, service_id, name, display_name, description, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,
          description=excluded.description, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.Description, string(document), v.ETag); err != nil {
		return v, err
	}
	return v, tx.Commit()
}

// GetWorkspace finds one workspace.
func (s *Store) GetWorkspace(id string) (model.Workspace, error) {
	var v model.Workspace
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, description, document_json, etag
	        FROM workspaces WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Description, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Workspace{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListWorkspaces returns a service's workspaces in stable ID order.
func (s *Store) ListWorkspaces(serviceID string) ([]model.Workspace, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, description, document_json, etag
        FROM workspaces WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Workspace, 0)
	for rows.Next() {
		var v model.Workspace
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Description, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteWorkspace removes a workspace and everything parented to it.
//
// Deleting the SCOPE is the whole operation: the workspace row and every
// resource inside it hang off it, so one delete takes the subtree. Removing
// only the workspace row would leave its contents addressable at a scope whose
// owner no longer exists.
func (s *Store) DeleteWorkspace(id string) error {
	return deleteScopedResource(s.db, "scopes", id)
}

// adoptScopes brings a database created before workspaces existed onto the
// scopes model.
//
// SQLite cannot alter a foreign key in place, so a table whose parent is still
// services(id) has to be rebuilt: create, copy, drop, rename. Without this an
// existing data directory keeps working for everything EXCEPT workspaces, which
// fail on the foreign key at insert time. That is a silent capability gap
// rather than a visible error, which is the worse of the two.
//
// The work is driven from sqlite_master rather than a hand-written list of
// tables, so a table added later cannot be forgotten here, and it is emitted as
// ONE script so the whole migration is a single all-or-nothing statement.
func (s *Store) adoptScopes() error {
	// Every service is its own scope. Backfilling first means the rebuilt
	// tables' foreign keys are satisfiable the moment they are created.
	if _, err := s.db.Exec(`INSERT INTO scopes (id, service_id) SELECT id, id FROM services WHERE id NOT IN (SELECT id FROM scopes)`); err != nil {
		return err
	}
	script, err := s.scopeRebuildScript()
	if err != nil || script == "" {
		return err
	}
	// Foreign keys stay off for the rebuild: the copy would otherwise be
	// checked against the very table being replaced.
	_, err = s.db.Exec("PRAGMA foreign_keys = OFF;\nBEGIN;\n" + script + "COMMIT;\nPRAGMA foreign_keys = ON;")
	if err != nil {
		_, _ = s.db.Exec("ROLLBACK;\nPRAGMA foreign_keys = ON;")
		return fmt.Errorf("adopt scopes: %w", err)
	}
	return nil
}

// scopeRebuildScript renders the DDL that repoints legacy parent keys, or "" if
// the database is already on the scopes model.
//
// The legacy definitions come back as ONE value rather than a row per table.
// Iterating rows would mean a per-row Scan whose error the query's own filter
// makes unreachable, and an unreachable error check is a branch that can only
// ever be wrong about itself. Unit separator joins the two fields, record
// separator joins the tables; neither can occur in a SQLite identifier or DDL.
func (s *Store) scopeRebuildScript() (string, error) {
	const (
		fieldSep  = "\x1f"
		recordSep = "\x1e"
	)
	var joined sql.NullString
	err := s.db.QueryRow(`SELECT group_concat(name || char(31) || sql, char(30)) FROM sqlite_master
	        WHERE type='table' AND sql LIKE '%REFERENCES services(id)%'
	          AND name NOT IN ('scopes', 'resource_documents')`).Scan(&joined)
	if err != nil {
		return "", err
	}
	if !joined.Valid || joined.String == "" {
		return "", nil
	}
	var script strings.Builder
	for _, record := range strings.Split(joined.String, recordSep) {
		name, ddl, found := strings.Cut(record, fieldSep)
		if !found {
			continue
		}
		rebuilt := strings.ReplaceAll(ddl, "REFERENCES services(id)", "REFERENCES scopes(id)")
		rebuilt = strings.Replace(rebuilt, "CREATE TABLE IF NOT EXISTS "+name, "CREATE TABLE "+name+"_scoped", 1)
		rebuilt = strings.Replace(rebuilt, "CREATE TABLE "+name, "CREATE TABLE "+name+"_scoped", 1)
		fmt.Fprintf(&script, "%s;\nINSERT INTO %s_scoped SELECT * FROM %s;\nDROP TABLE %s;\nALTER TABLE %s_scoped RENAME TO %s;\n",
			rebuilt, name, name, name, name, name)
	}
	return script.String(), nil
}

// UpsertAuthorizationProvider creates or replaces a credential-manager provider.
func (s *Store) UpsertAuthorizationProvider(v model.AuthorizationProvider) (model.AuthorizationProvider, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO authorization_providers (id, service_id, name, display_name, identity_provider, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,
          identity_provider=excluded.identity_provider, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, v.IdentityProvider, string(document), v.ETag)
	return v, err
}

// GetAuthorizationProvider finds one provider.
func (s *Store) GetAuthorizationProvider(id string) (model.AuthorizationProvider, error) {
	var v model.AuthorizationProvider
	var document string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, identity_provider, document_json, etag
	        FROM authorization_providers WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.IdentityProvider, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthorizationProvider{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAuthorizationProviders returns a service's providers in stable ID order.
func (s *Store) ListAuthorizationProviders(serviceID string) ([]model.AuthorizationProvider, error) {
	rows, err := s.db.Query(`SELECT service_id, name, display_name, identity_provider, document_json, etag
        FROM authorization_providers WHERE lower(service_id)=lower(?) ORDER BY id`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.AuthorizationProvider, 0)
	for rows.Next() {
		var v model.AuthorizationProvider
		var document string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.IdentityProvider, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAuthorizationProvider removes a provider and, by cascade, its stored
// credentials. Deleting a provider revokes every credential under it, which is
// the behaviour an operator expects when withdrawing an integration.
func (s *Store) DeleteAuthorizationProvider(id string) error {
	return deleteScopedResource(s.db, "authorization_providers", id)
}

// UpsertAuthorization creates or replaces one stored credential.
func (s *Store) UpsertAuthorization(v model.Authorization) (model.Authorization, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO authorizations (id, provider_id, name, authorization_type, oauth2_grant_type, status, error_message, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET authorization_type=excluded.authorization_type,
          oauth2_grant_type=excluded.oauth2_grant_type, status=excluded.status, error_message=excluded.error_message,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.ProviderID, v.Name, v.AuthorizationType, v.OAuth2GrantType, v.Status, v.ErrorMsg, string(document), v.ETag)
	return v, err
}

// GetAuthorization finds one stored credential.
func (s *Store) GetAuthorization(id string) (model.Authorization, error) {
	var v model.Authorization
	var document string
	err := s.db.QueryRow(`SELECT provider_id, name, authorization_type, oauth2_grant_type, status, error_message, document_json, etag
	        FROM authorizations WHERE lower(id)=lower(?)`, id).
		Scan(&v.ProviderID, &v.Name, &v.AuthorizationType, &v.OAuth2GrantType, &v.Status, &v.ErrorMsg, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Authorization{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAuthorizations returns a provider's credentials in stable ID order.
func (s *Store) ListAuthorizations(providerID string) ([]model.Authorization, error) {
	rows, err := s.db.Query(`SELECT provider_id, name, authorization_type, oauth2_grant_type, status, error_message, document_json, etag
        FROM authorizations WHERE lower(provider_id)=lower(?) ORDER BY id`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.Authorization, 0)
	for rows.Next() {
		var v model.Authorization
		var document string
		if err := rows.Scan(&v.ProviderID, &v.Name, &v.AuthorizationType, &v.OAuth2GrantType, &v.Status, &v.ErrorMsg, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAuthorization removes one stored credential.
func (s *Store) DeleteAuthorization(id string) error {
	return deleteScopedResource(s.db, "authorizations", id)
}

// UpsertAuthorizationAccessPolicy creates or replaces an access policy.
func (s *Store) UpsertAuthorizationAccessPolicy(v model.AuthorizationAccessPolicy) (model.AuthorizationAccessPolicy, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO authorization_access_policies (id, authorization_id, name, tenant_id, object_id, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET tenant_id=excluded.tenant_id,
          object_id=excluded.object_id, document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.AuthorizationID, v.Name, v.TenantID, v.ObjectID, string(document), v.ETag)
	return v, err
}

// GetAuthorizationAccessPolicy finds one access policy.
func (s *Store) GetAuthorizationAccessPolicy(id string) (model.AuthorizationAccessPolicy, error) {
	var v model.AuthorizationAccessPolicy
	var document string
	err := s.db.QueryRow(`SELECT authorization_id, name, tenant_id, object_id, document_json, etag
	        FROM authorization_access_policies WHERE lower(id)=lower(?)`, id).
		Scan(&v.AuthorizationID, &v.Name, &v.TenantID, &v.ObjectID, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AuthorizationAccessPolicy{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListAuthorizationAccessPolicies returns a credential's access policies.
func (s *Store) ListAuthorizationAccessPolicies(authorizationID string) ([]model.AuthorizationAccessPolicy, error) {
	rows, err := s.db.Query(`SELECT authorization_id, name, tenant_id, object_id, document_json, etag
        FROM authorization_access_policies WHERE lower(authorization_id)=lower(?) ORDER BY id`, authorizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]model.AuthorizationAccessPolicy, 0)
	for rows.Next() {
		var v model.AuthorizationAccessPolicy
		var document string
		if err := rows.Scan(&v.AuthorizationID, &v.Name, &v.TenantID, &v.ObjectID, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteAuthorizationAccessPolicy removes an access policy.
func (s *Store) DeleteAuthorizationAccessPolicy(id string) error {
	return deleteScopedResource(s.db, "authorization_access_policies", id)
}

// UpsertRoleAssignment creates or replaces a role assignment.
func (s *Store) UpsertRoleAssignment(v rbac.Assignment) (rbac.Assignment, error) {
	document, err := json.Marshal(v.Document)
	if err != nil {
		return v, err
	}
	v.ETag = newETag()
	_, err = s.db.Exec(`INSERT INTO role_assignments (id, scope, name, principal_id, principal_type, role_definition_id, document_json, etag)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET principal_id=excluded.principal_id,
          principal_type=excluded.principal_type, role_definition_id=excluded.role_definition_id,
          document_json=excluded.document_json, etag=excluded.etag`,
		v.ID(), v.Scope, v.Name, v.PrincipalID, v.PrincipalType, v.RoleDefinitionID, string(document), v.ETag)
	return v, err
}

// GetRoleAssignment finds one role assignment.
func (s *Store) GetRoleAssignment(id string) (rbac.Assignment, error) {
	var v rbac.Assignment
	var document string
	err := s.db.QueryRow(`SELECT scope, name, principal_id, principal_type, role_definition_id, document_json, etag
	        FROM role_assignments WHERE lower(id)=lower(?)`, id).
		Scan(&v.Scope, &v.Name, &v.PrincipalID, &v.PrincipalType, &v.RoleDefinitionID, &document, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return rbac.Assignment{}, ErrNotFound
	}
	if err == nil {
		_ = json.Unmarshal([]byte(document), &v.Document)
	}
	return v, err
}

// ListRoleAssignments returns every assignment, in stable ID order.
//
// Every assignment, not just those at one scope: authorization has to consider
// assignments made ABOVE the resource being touched, and filtering here would
// hide exactly the ones that grant access by inheritance.
func (s *Store) ListRoleAssignments() ([]rbac.Assignment, error) {
	rows, err := s.db.Query(`SELECT scope, name, principal_id, principal_type, role_definition_id, document_json, etag
        FROM role_assignments ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]rbac.Assignment, 0)
	for rows.Next() {
		var v rbac.Assignment
		var document string
		if err := rows.Scan(&v.Scope, &v.Name, &v.PrincipalID, &v.PrincipalType, &v.RoleDefinitionID, &document, &v.ETag); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(document), &v.Document)
		values = append(values, v)
	}
	return values, rows.Err()
}

// DeleteRoleAssignment removes a role assignment.
func (s *Store) DeleteRoleAssignment(id string) error {
	return deleteScopedResource(s.db, "role_assignments", id)
}

// LinkKind names an association that Azure also exposes as a link resource.
//
// Links are not their own store. Each kind below points at an association the
// emulator already keeps, and the link surface reads and writes THAT. The only
// thing a link adds is a name, because Azure lets a client choose one, so the
// name is a column on the association rather than a row somewhere else.
type LinkKind int

const (
	// LinkProductAPIKind is the product-to-API association.
	LinkProductAPIKind LinkKind = iota
	// LinkProductGroupKind is the product-to-group association.
	LinkProductGroupKind
	// LinkResourceTagKind is the tag-to-resource association. Its owner is the
	// TAG and its target is the tagged resource, which is the reverse of how
	// the table reads, because that is the direction the link surface asks in.
	LinkResourceTagKind
)

// linkTable describes where one kind of association lives.
func (k LinkKind) linkTable() (table, owner, target string) {
	switch k {
	case LinkProductAPIKind:
		return "product_apis", "product_id", "api_id"
	case LinkProductGroupKind:
		return "product_groups", "product_id", "group_id"
	default:
		return "resource_tags", "tag_id", "resource_id"
	}
}

// SetLinkName records the name a client gave an association's link resource.
func (s *Store) SetLinkName(kind LinkKind, ownerID, targetID, name string) error {
	table, owner, target := kind.linkTable()
	result, err := s.db.Exec(
		`UPDATE `+table+` SET link_name=? WHERE lower(`+owner+`)=lower(?) AND lower(`+target+`)=lower(?)`,
		name, ownerID, targetID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrNotFound
	}
	return nil
}

// LinkNames returns each associated target and the link name it carries.
//
// A target whose association was made through the older path (`PUT
// /products/{id}/apis/{apiId}`) has no stored name, and comes back with an
// empty one. Naming it is the caller's job, because the rule for doing so is a
// presentation decision the store should not be making.
func (s *Store) LinkNames(kind LinkKind, ownerID string) (map[string]string, error) {
	table, owner, target := kind.linkTable()
	rows, err := s.db.Query(
		`SELECT `+target+`, link_name FROM `+table+` WHERE lower(`+owner+`)=lower(?) ORDER BY `+target, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var targetID, name string
		if err := rows.Scan(&targetID, &name); err != nil {
			return nil, err
		}
		values[targetID] = name
	}
	return values, rows.Err()
}

// ListTaggedResources returns the resource IDs a tag is attached to.
func (s *Store) ListTaggedResources(tagID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT resource_id FROM resource_tags WHERE lower(tag_id)=lower(?) ORDER BY resource_id`, tagID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []string{}
	for rows.Next() {
		var resourceID string
		if err := rows.Scan(&resourceID); err != nil {
			return nil, err
		}
		values = append(values, resourceID)
	}
	return values, rows.Err()
}
