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
	openDB     = sql.Open
	readRandom = rand.Read
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
CREATE TABLE IF NOT EXISTS apis (
  id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, path TEXT NOT NULL,
  service_url TEXT NOT NULL, protocols_json TEXT NOT NULL,
  subscription_required INTEGER NOT NULL, etag TEXT NOT NULL
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
	_, err := s.db.Exec(`INSERT INTO services
	    (id, subscription_id, resource_group, name, location, sku_name, sku_capacity, publisher_name, publisher_email, provisioning_state, etag)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	    ON CONFLICT(id) DO UPDATE SET location=excluded.location, sku_name=excluded.sku_name,
	      sku_capacity=excluded.sku_capacity, publisher_name=excluded.publisher_name,
	      publisher_email=excluded.publisher_email, provisioning_state=excluded.provisioning_state, etag=excluded.etag`,
		v.ID(), v.SubscriptionID, v.ResourceGroup, v.Name, v.Location, v.SKUName,
		v.SKUCapacity, v.PublisherName, v.PublisherEmail, v.ProvisioningState, v.ETag)
	return v, err
}

// GetService finds one service by ARM ID.
func (s *Store) GetService(id string) (model.Service, error) {
	var v model.Service
	err := s.db.QueryRow(`SELECT subscription_id, resource_group, name, location, sku_name,
	      sku_capacity, publisher_name, publisher_email, provisioning_state, etag FROM services WHERE lower(id)=lower(?)`, id).
		Scan(&v.SubscriptionID, &v.ResourceGroup, &v.Name, &v.Location, &v.SKUName,
			&v.SKUCapacity, &v.PublisherName, &v.PublisherEmail, &v.ProvisioningState, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}

// DeleteService removes a service and its children.
func (s *Store) DeleteService(id string) error {
	result, err := s.db.Exec(`DELETE FROM services WHERE lower(id)=lower(?)`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

// ListServices returns services in stable ID order.
func (s *Store) ListServices() ([]model.Service, error) {
	rows, err := s.db.Query(`SELECT subscription_id, resource_group, name, location, sku_name,
	      sku_capacity, publisher_name, publisher_email, provisioning_state, etag FROM services ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.Service
	for rows.Next() {
		var v model.Service
		if err := rows.Scan(&v.SubscriptionID, &v.ResourceGroup, &v.Name, &v.Location,
			&v.SKUName, &v.SKUCapacity, &v.PublisherName, &v.PublisherEmail,
			&v.ProvisioningState, &v.ETag); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// UpsertAPI creates or replaces an API.
func (s *Store) UpsertAPI(v model.API) (model.API, error) {
	v.ETag = newETag()
	protocols, _ := json.Marshal(v.Protocols)
	_, err := s.db.Exec(`INSERT INTO apis
    (id, service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, path=excluded.path,
      service_url=excluded.service_url, protocols_json=excluded.protocols_json,
      subscription_required=excluded.subscription_required, etag=excluded.etag`,
		v.ID(), v.ServiceID, v.Name, v.DisplayName, strings.Trim(v.Path, "/"), v.ServiceURL,
		string(protocols), v.SubscriptionRequired, v.ETag)
	return v, err
}

// GetAPI finds one API by ARM ID.
func (s *Store) GetAPI(id string) (model.API, error) {
	var v model.API
	var protocols string
	err := s.db.QueryRow(`SELECT service_id, name, display_name, path, service_url,
      protocols_json, subscription_required, etag FROM apis WHERE lower(id)=lower(?)`, id).
		Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Path, &v.ServiceURL,
			&protocols, &v.SubscriptionRequired, &v.ETag)
	if errors.Is(err, sql.ErrNoRows) {
		return model.API{}, ErrNotFound
	}
	if err != nil {
		return model.API{}, err
	}
	_ = json.Unmarshal([]byte(protocols), &v.Protocols)
	return v, nil
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

// LinkProductAPI associates an API with a product.
func (s *Store) LinkProductAPI(productID, apiID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO product_apis (product_id, api_id) VALUES (?, ?)`, productID, apiID)
	return err
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

// UpsertPolicy stores policy XML for a scope.
func (s *Store) UpsertPolicy(v model.Policy) (model.Policy, error) {
	v.ETag = newETag()
	_, err := s.db.Exec(`INSERT INTO policies (scope_id, format, value, etag) VALUES (?, ?, ?, ?)
      ON CONFLICT(scope_id) DO UPDATE SET format=excluded.format, value=excluded.value, etag=excluded.etag`,
		v.ScopeID, v.Format, v.Value, v.ETag)
	return v, err
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
	rows, err := db.Query(`SELECT service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag FROM apis ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []model.API
	for rows.Next() {
		var v model.API
		var protocols string
		if err := rows.Scan(&v.ServiceID, &v.Name, &v.DisplayName, &v.Path, &v.ServiceURL, &protocols, &v.SubscriptionRequired, &v.ETag); err != nil {
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
