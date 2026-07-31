package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

func TestStoreResourceLifecycle(t *testing.T) {
	st, err := Open(t.TempDir(), clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	service := model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc", Location: "local", SKUName: "Developer", SKUCapacity: 1, PublisherName: "Local", PublisherEmail: "local@example.test", Document: map[string]any{"tags": map[string]any{"environment": "test"}}}
	service, err = st.UpsertService(service)
	if err != nil {
		t.Fatal(err)
	}
	if service.ETag == "" || service.ProvisioningState != "Succeeded" {
		t.Fatalf("service = %+v", service)
	}
	gotService, err := st.GetService(service.ID())
	if err != nil || gotService.Name != "svc" || gotService.PublisherEmail != "local@example.test" || gotService.Document["tags"].(map[string]any)["environment"] != "test" {
		t.Fatalf("GetService = %+v, %v", gotService, err)
	}
	if _, err := st.GetService("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing service = %v", err)
	}

	api := model.API{ServiceID: service.ID(), Name: "api", DisplayName: "API", Path: "/api/", ServiceURL: "https://backend.test", Protocols: []string{"https"}, SubscriptionRequired: true}
	api, err = st.UpsertAPI(api)
	if err != nil {
		t.Fatal(err)
	}
	if api.ETag == "" {
		t.Fatal("API ETag missing")
	}
	if api.Revision != "1" || !api.IsCurrent || api.CreatedAt == 0 || api.UpdatedAt == 0 {
		t.Fatalf("API revision metadata = %+v", api)
	}
	gotAPI, err := st.GetAPI(api.ID())
	if err != nil || gotAPI.Path != "api" || len(gotAPI.Protocols) != 1 {
		t.Fatalf("GetAPI = %+v, %v", gotAPI, err)
	}
	if _, err := st.GetAPI("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing API = %v", err)
	}

	if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", DisplayName: "Get", Method: "get", URLTemplate: "/{id}"}); err != nil {
		t.Fatal(err)
	}
	product, err := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "product", DisplayName: "Product", State: "published"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductAPI(product.ID(), api.ID()); err != nil {
		t.Fatal(err)
	}
	subscription, err := st.UpsertSubscription(model.Subscription{ServiceID: service.ID(), Name: "sub", DisplayName: "Sub", Scope: product.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if subscription.PrimaryKey == "" || subscription.SecondaryKey == "" || subscription.State != "active" {
		t.Fatalf("subscription = %+v", subscription)
	}
	policy, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Format: "rawxml", Value: "<policies/>"})
	if err != nil {
		t.Fatal(err)
	}
	gotPolicy, err := st.GetPolicy(api.ID())
	if err != nil || gotPolicy.Value != policy.Value {
		t.Fatalf("GetPolicy = %+v, %v", gotPolicy, err)
	}
	if _, err := st.GetPolicy("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing policy = %v", err)
	}

	services, apis, operations, products, links, subscriptions, policies, err := st.RuntimeData()
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || len(apis) != 1 || len(operations) != 1 || len(products) != 1 ||
		len(links[product.ID()]) != 1 || len(subscriptions) != 1 || len(policies) != 1 {
		t.Fatalf("runtime sizes = %d %d %d %d %#v %d %d", len(services), len(apis), len(operations), len(products), links, len(subscriptions), len(policies))
	}
	if services[0].Document["tags"].(map[string]any)["environment"] != "test" {
		t.Fatalf("listed document = %#v", services[0].Document)
	}
	if err := st.DeleteService(service.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteService(service.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestOpenMemoryIsolationAndIDs(t *testing.T) {
	a, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if NewOpaqueID() == NewOpaqueID() {
		t.Fatal("opaque IDs collided")
	}
	if values, err := b.ListServices(); err != nil || len(values) != 0 {
		t.Fatalf("isolated store = %v, %v", values, err)
	}
}

func TestAPIAndOperationLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", DisplayName: "API", ServiceURL: "https://backend"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "other", DisplayName: "Other", ServiceURL: "https://backend"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: "GET", URLTemplate: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertOperation(model.Operation{APIID: other.ID(), Name: "other", Method: "GET", URLTemplate: "/"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: "<policies/>"}); err != nil {
		t.Fatal(err)
	}

	apis, err := st.ListAPIs(strings.ToUpper(service.ID()))
	if err != nil || len(apis) != 2 {
		t.Fatalf("ListAPIs = %#v, %v", apis, err)
	}
	operations, err := st.ListOperations(strings.ToUpper(api.ID()))
	if err != nil || len(operations) != 1 || operations[0].Name != "get" {
		t.Fatalf("ListOperations = %#v, %v", operations, err)
	}
	got, err := st.GetOperation(strings.ToUpper(operation.APIID + "/operations/" + operation.Name))
	if err != nil || got.Method != "GET" {
		t.Fatalf("GetOperation = %#v, %v", got, err)
	}
	if _, err := st.GetOperation("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operation = %v", err)
	}
	if err := st.DeleteAPI(api.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetOperation(operation.APIID + "/operations/" + operation.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("operation survived API deletion: %v", err)
	}
	if _, err := st.GetPolicy(api.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("policy survived API deletion: %v", err)
	}
	if err := st.DeleteOperation(other.ID() + "/operations/other"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteOperation(other.ID() + "/operations/other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second operation delete = %v", err)
	}
}

func TestScopedDeleteRollsBackFailures(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", DisplayName: "API", ServiceURL: "https://backend"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: "<policies/>"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER reject_policy_delete BEFORE DELETE ON policies BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAPI(api.ID()); err == nil {
		t.Fatal("policy delete failure was ignored")
	}
	if _, err := st.GetAPI(api.ID()); err != nil {
		t.Fatalf("API was not rolled back: %v", err)
	}
	if _, err := st.db.Exec(`DROP TRIGGER reject_policy_delete; CREATE TRIGGER reject_api_delete BEFORE DELETE ON apis BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAPI(api.ID()); err == nil {
		t.Fatal("API delete failure was ignored")
	}
	if _, err := st.GetPolicy(api.ID()); err != nil {
		t.Fatalf("policy deletion was not rolled back: %v", err)
	}
}

func TestOpenAndOpaqueIDFailures(t *testing.T) {
	oldOpen, oldRead := openDB, readRandom
	t.Cleanup(func() {
		openDB = oldOpen
		readRandom = oldRead
	})

	want := errors.New("open failed")
	openDB = func(string, string) (*sql.DB, error) { return nil, want }
	if _, err := Open("", clock.New()); !errors.Is(err, want) {
		t.Fatalf("Open error = %v", err)
	}

	readRandom = func([]byte) (int, error) { return 0, want }
	defer func() {
		if recovered := recover(); !errors.Is(recovered.(error), want) {
			t.Fatalf("panic = %v", recovered)
		}
	}()
	NewOpaqueID()
}

func TestClosedStoreErrors(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	service := model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"}
	api := model.API{ServiceID: service.ID(), Name: "api"}
	for name, call := range map[string]func() error{
		"delete": func() error { return st.DeleteService(service.ID()) },
		"list": func() error {
			_, err := st.ListServices()
			return err
		},
		"get API": func() error {
			_, err := st.GetAPI(api.ID())
			return err
		},
		"get policy": func() error {
			_, err := st.GetPolicy("policy")
			return err
		},
		"runtime": func() error {
			_, _, _, _, _, _, _, err := st.RuntimeData()
			return err
		},
	} {
		if err := call(); err == nil {
			t.Errorf("%s succeeded on closed store", name)
		}
	}
}

func TestRuntimeDataStopsAtEachQueryFailure(t *testing.T) {
	tables := []string{"apis", "api_revision_metadata", "operations", "products", "product_apis", "subscriptions"}
	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			st, err := Open("", clock.New())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if _, err := st.db.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, _, _, _, err := st.RuntimeData(); err == nil {
				t.Fatal("RuntimeData succeeded with missing table")
			}
		})
	}
}

func TestScanFunctionsRejectMalformedRows(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		insert string
		scan   func(*sql.DB) error
	}{
		{
			"services",
			`CREATE TABLE services (id, subscription_id, resource_group, name, location, sku_name, sku_capacity, publisher_name, publisher_email, provisioning_state, etag);
			 CREATE TABLE resource_documents (id, document_json)`,
			`INSERT INTO services VALUES ('id', NULL, '', '', '', '', 0, '', '', '', '')`,
			func(db *sql.DB) error {
				_, err := (&Store{db: db}).ListServices()
				return err
			},
		},
		{
			"apis",
			`CREATE TABLE apis (id, service_id, name, display_name, path, service_url, protocols_json, subscription_required, etag);
			 CREATE TABLE api_revision_metadata (api_id, revision, description, is_current, created_at, updated_at);
			 CREATE TABLE api_version_metadata (api_id, version, version_set_id)`,
			`INSERT INTO apis VALUES ('id', NULL, '', '', '', '', '[]', 0, '')`,
			func(db *sql.DB) error { _, err := scanAPIs(db); return err },
		},
		{
			"version sets",
			`CREATE TABLE api_version_sets (id, service_id, name, display_name, versioning_scheme, version_header_name, version_query_name, description, etag)`,
			`INSERT INTO api_version_sets VALUES ('id', 'service', NULL, '', '', '', '', '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListAPIVersionSets("service"); return err },
		},
		{
			"releases",
			`CREATE TABLE api_releases (id, api_id, name, target_api_id, notes, created_at, updated_at, etag)`,
			`INSERT INTO api_releases VALUES ('id', 'id', NULL, '', '', 0, 0, '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListAPIReleases("id"); return err },
		},
		{
			"operations",
			`CREATE TABLE operations (id, api_id, name, display_name, method, url_template, etag)`,
			`INSERT INTO operations VALUES ('id', NULL, '', '', '', '', '')`,
			func(db *sql.DB) error { _, err := scanOperations(db); return err },
		},
		{
			"products",
			`CREATE TABLE products (id, service_id, name, display_name, state, approval_required, etag)`,
			`INSERT INTO products VALUES ('id', NULL, '', '', '', 0, '')`,
			func(db *sql.DB) error { _, err := scanProducts(db); return err },
		},
		{
			"links",
			`CREATE TABLE product_apis (product_id, api_id)`,
			`INSERT INTO product_apis VALUES (NULL, '')`,
			func(db *sql.DB) error { _, err := scanLinks(db); return err },
		},
		{
			"subscriptions",
			`CREATE TABLE subscriptions (id, service_id, name, display_name, scope, state, primary_key, secondary_key, etag)`,
			`INSERT INTO subscriptions VALUES ('id', NULL, '', '', '', '', '', '', '')`,
			func(db *sql.DB) error { _, err := scanSubscriptions(db); return err },
		},
		{
			"policies",
			`CREATE TABLE policies (scope_id, format, value, etag)`,
			`INSERT INTO policies VALUES (NULL, '', '', '')`,
			func(db *sql.DB) error { _, err := scanPolicies(db); return err },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(test.schema); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.insert); err != nil {
				t.Fatal(err)
			}
			if err := test.scan(db); err == nil {
				t.Fatal("malformed row was accepted")
			}
		})
	}
}

func TestUpsertServiceTransactionErrors(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertService(model.Service{}); err == nil {
			t.Fatal("closed store accepted service")
		}
	})

	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service := model.Service{Name: "bad", Document: map[string]any{"unsupported": func() {}}}
		if _, err := st.UpsertService(service); err == nil {
			t.Fatal("unsupported document was accepted")
		}
		if _, err := st.GetService(service.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("service transaction was not rolled back: %v", err)
		}
	})

	t.Run("document write", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.db.Exec(`CREATE TRIGGER reject_document BEFORE INSERT ON resource_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		service := model.Service{Name: "bad", Document: map[string]any{"location": "local"}}
		if _, err := st.UpsertService(service); err == nil {
			t.Fatal("rejected document was accepted")
		}
		if _, err := st.GetService(service.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("service transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertAPITransactionErrors(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertAPI(model.API{}); err == nil {
			t.Fatal("closed store accepted API")
		}
	})

	t.Run("metadata", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, err := st.UpsertService(model.Service{Name: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`CREATE TRIGGER reject_api_metadata BEFORE INSERT ON api_revision_metadata BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		api := model.API{ServiceID: service.ID(), Name: "api"}
		if _, err := st.UpsertAPI(api); err == nil {
			t.Fatal("rejected API metadata was accepted")
		}
		if _, err := st.GetAPI(api.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("API transaction was not rolled back: %v", err)
		}
	})

	t.Run("version metadata", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, err := st.UpsertService(model.Service{Name: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`CREATE TRIGGER reject_api_version BEFORE INSERT ON api_version_metadata BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		api := model.API{ServiceID: service.ID(), Name: "api"}
		if _, err := st.UpsertAPI(api); err == nil {
			t.Fatal("rejected API version metadata was accepted")
		}
		if _, err := st.GetAPI(api.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("API transaction was not rolled back: %v", err)
		}
	})
}

func TestCloneAPIRevisionTransactions(t *testing.T) {
	newSource := func(t *testing.T) (*Store, model.API) {
		t.Helper()
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		service, err := st.UpsertService(model.Service{Name: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", DisplayName: "API", ServiceURL: "https://backend"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: "GET", URLTemplate: "/"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: "<policies/>"}); err != nil {
			t.Fatal(err)
		}
		return st, api
	}

	t.Run("default revision", func(t *testing.T) {
		st, source := newSource(t)
		target := source
		target.Name, target.Revision = "api;rev=2", ""
		cloned, err := st.CloneAPIRevision(source.ID(), target)
		if err != nil || cloned.Revision != "2" || cloned.IsCurrent {
			t.Fatalf("cloned API = %+v, %v", cloned, err)
		}
	})

	t.Run("invalid version set", func(t *testing.T) {
		st, source := newSource(t)
		target := source
		target.Name, target.VersionSetID = "api;rev=2", "/missing"
		if _, err := st.CloneAPIRevision(source.ID(), target); !errors.Is(err, ErrNotFound) {
			t.Fatalf("invalid version set = %v", err)
		}
	})

	t.Run("begin", func(t *testing.T) {
		st, source := newSource(t)
		_ = st.Close()
		if _, err := st.CloneAPIRevision(source.ID(), source); err == nil {
			t.Fatal("closed store cloned revision")
		}
	})

	t.Run("api row", func(t *testing.T) {
		st, source := newSource(t)
		target := source
		target.ServiceID, target.Name = "/missing", "api;rev=2"
		if _, err := st.CloneAPIRevision(source.ID(), target); err == nil {
			t.Fatal("invalid API row was cloned")
		}
	})

	for _, test := range []struct{ name, trigger string }{
		{"metadata", `CREATE TRIGGER reject_clone_metadata BEFORE INSERT ON api_revision_metadata WHEN NEW.revision='2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"version metadata", `CREATE TRIGGER reject_clone_version BEFORE INSERT ON api_version_metadata WHEN NEW.api_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"operations", `CREATE TRIGGER reject_clone_operation BEFORE INSERT ON operations WHEN NEW.api_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"policy", `CREATE TRIGGER reject_clone_policy BEFORE INSERT ON policies WHEN NEW.scope_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
	} {
		t.Run(test.name, func(t *testing.T) {
			st, source := newSource(t)
			if _, err := st.db.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			target := source
			target.Name, target.Revision = "api;rev=2", "2"
			if _, err := st.CloneAPIRevision(source.ID(), target); err == nil {
				t.Fatal("rejected revision clone succeeded")
			}
			if _, err := st.GetAPI(target.ID()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("revision clone was not rolled back: %v", err)
			}
		})
	}
}

func TestAPIReleaseTransactions(t *testing.T) {
	setup := func(t *testing.T) (*Store, model.APIRelease) {
		t.Helper()
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		base, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
		target := base
		target.Name, target.Revision = "api;rev=2", "2"
		target, _ = st.CloneAPIRevision(base.ID(), target)
		return st, model.APIRelease{APIID: base.ID(), Name: "release", TargetAPIID: target.ID()}
	}

	tests := []struct {
		name string
		run  func(*testing.T, *Store, model.APIRelease)
	}{
		{"missing target", func(t *testing.T, st *Store, release model.APIRelease) {
			release.TargetAPIID = "/missing"
			if _, err := st.UpsertAPIRelease(release); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v", err)
			}
		}},
		{"cross API", func(t *testing.T, st *Store, release model.APIRelease) {
			release.APIID += "-other"
			if _, err := st.UpsertAPIRelease(release); !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v", err)
			}
		}},
		{"existing query", func(t *testing.T, st *Store, release model.APIRelease) {
			_, _ = st.db.Exec(`DROP TABLE api_releases`)
			if _, err := st.UpsertAPIRelease(release); err == nil {
				t.Fatal("query error ignored")
			}
		}},
		{"release write", func(t *testing.T, st *Store, release model.APIRelease) {
			_, _ = st.db.Exec(`CREATE TRIGGER reject_release BEFORE INSERT ON api_releases BEGIN SELECT RAISE(FAIL, 'rejected'); END`)
			if _, err := st.UpsertAPIRelease(release); err == nil {
				t.Fatal("write error ignored")
			}
		}},
		{"promotion", func(t *testing.T, st *Store, release model.APIRelease) {
			_, _ = st.db.Exec(`CREATE TRIGGER reject_promotion BEFORE UPDATE ON api_revision_metadata BEGIN SELECT RAISE(FAIL, 'rejected'); END`)
			if _, err := st.UpsertAPIRelease(release); err == nil {
				t.Fatal("promotion error ignored")
			}
		}},
		{"missing metadata", func(t *testing.T, st *Store, release model.APIRelease) {
			_, _ = st.db.Exec(`DELETE FROM api_revision_metadata`)
			if _, err := st.UpsertAPIRelease(release); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v", err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { st, release := setup(t); test.run(t, st, release) })
	}
	t.Run("begin", func(t *testing.T) {
		st, release := setup(t)
		original := beginReleaseTxn
		beginReleaseTxn = func(*sql.DB) (*sql.Tx, error) { return nil, errors.New("begin failed") }
		defer func() { beginReleaseTxn = original }()
		if _, err := st.UpsertAPIRelease(release); err == nil {
			t.Fatal("begin error ignored")
		}
	})
}

func TestAPIVersionSetOwnership(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	owner, _ := st.UpsertService(model.Service{Name: "owner"})
	other, _ := st.UpsertService(model.Service{Name: "other"})
	versionSet, err := st.UpsertAPIVersionSet(model.APIVersionSet{ServiceID: owner.ID(), Name: "versions", DisplayName: "Versions", VersioningScheme: "Segment"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAPI(model.API{ServiceID: other.ID(), Name: "api", Version: "v1", VersionSetID: versionSet.ID()}); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-service version set = %v", err)
	}
}

func TestScanFunctionsQueryErrors(t *testing.T) {
	db, err := sql.Open("sqlite", "file:empty-scans?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scans := []func(*sql.DB) error{
		func(db *sql.DB) error { _, err := scanAPIs(db); return err },
		func(db *sql.DB) error { _, err := scanOperations(db); return err },
		func(db *sql.DB) error { _, err := scanProducts(db); return err },
		func(db *sql.DB) error { _, err := scanLinks(db); return err },
		func(db *sql.DB) error { _, err := scanSubscriptions(db); return err },
		func(db *sql.DB) error { _, err := scanPolicies(db); return err },
	}
	for index, scan := range scans {
		if err := scan(db); err == nil {
			t.Errorf("scan %d succeeded: %s", index, fmt.Sprint(err))
		}
	}
}
