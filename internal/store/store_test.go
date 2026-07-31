package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	subscription, err := st.UpsertSubscription(model.Subscription{ServiceID: service.ID(), Name: "sub", DisplayName: "Sub", Scope: product.ID(), Document: map[string]any{"primaryKey": "root", "secondaryKey": "root-two", "custom": true, "properties": map[string]any{"primaryKey": "nested", "secondaryKey": "nested-two"}}})
	if err != nil {
		t.Fatal(err)
	}
	if subscription.PrimaryKey == "" || subscription.SecondaryKey == "" || subscription.State != "active" || subscription.Document["primaryKey"] != nil || subscription.Document["custom"] != true {
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
	if services[0].Document["tags"].(map[string]any)["environment"] != "test" || subscriptions[0].Document["custom"] != true || subscriptions[0].Document["properties"].(map[string]any)["primaryKey"] != nil {
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
	operation, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: "GET", URLTemplate: "/", Document: map[string]any{"properties": map[string]any{"description": "retained"}}})
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
	if err != nil || got.Method != "GET" || got.Document["properties"].(map[string]any)["description"] != "retained" {
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

func TestUpsertOperationTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertOperation(model.Operation{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("operation accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertOperation(model.Operation{}); err == nil {
			t.Fatal("closed store accepted an operation")
		}
	})
	t.Run("operation row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertOperation(model.Operation{APIID: "/missing", Name: "operation"}); err == nil {
			t.Fatal("operation with a missing API was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_operation_document BEFORE INSERT ON operation_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		operation := model.Operation{APIID: api.ID(), Name: "operation"}
		if _, err := st.UpsertOperation(operation); err == nil {
			t.Fatal("rejected operation document was accepted")
		}
		if _, err := st.GetOperation(operation.APIID + "/operations/" + operation.Name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("operation transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertProductTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertProduct(model.Product{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("product accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertProduct(model.Product{}); err == nil {
			t.Fatal("closed store accepted a product")
		}
	})
	t.Run("product row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertProduct(model.Product{ServiceID: "/missing", Name: "product"}); err == nil {
			t.Fatal("product with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_product_document BEFORE INSERT ON product_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		product := model.Product{ServiceID: service.ID(), Name: "product"}
		if _, err := st.UpsertProduct(product); err == nil {
			t.Fatal("rejected product document was accepted")
		}
		if _, err := st.GetProduct(product.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("product transaction was not rolled back: %v", err)
		}
	})
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

func TestScopedDeleteRollsBackTagCleanupFailure(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	tag, err := st.UpsertTag(model.Tag{ServiceID: service.ID(), Name: "tag", DisplayName: "Tag"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AssignTag(api.ID(), tag.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER reject_resource_tag_delete BEFORE DELETE ON resource_tags BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAPI(api.ID()); err == nil {
		t.Fatal("resource tag cleanup failure was ignored")
	}
	if _, err := st.GetAPI(api.ID()); err != nil {
		t.Fatalf("API was not rolled back: %v", err)
	}
	if _, err := st.GetResourceTag(api.ID(), tag.ID()); err != nil {
		t.Fatalf("tag association was not rolled back: %v", err)
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
		"import API": func() error {
			_, err := st.ImportAPI(api, model.APIDefinition{}, nil, nil)
			return err
		},
		"get API definition": func() error {
			_, err := st.GetAPIDefinition(api.ID())
			return err
		},
		"get policy": func() error {
			_, err := st.GetPolicy("policy")
			return err
		},
		"upsert named value": func() error {
			_, err := st.UpsertNamedValue(model.NamedValue{})
			return err
		},
		"get named value": func() error {
			_, err := st.GetNamedValue("named")
			return err
		},
		"list named values": func() error {
			_, err := st.ListNamedValues("service")
			return err
		},
		"delete named value": func() error { return st.DeleteNamedValue("named") },
		"upsert backend":     func() error { _, err := st.UpsertBackend(model.Backend{}); return err },
		"get backend":        func() error { _, err := st.GetBackend("backend"); return err },
		"list backends":      func() error { _, err := st.ListBackends("service"); return err },
		"delete backend":     func() error { return st.DeleteBackend("backend") },
		"upsert certificate": func() error { _, err := st.UpsertCertificate(model.Certificate{}); return err },
		"get certificate":    func() error { _, err := st.GetCertificate("certificate"); return err },
		"list certificates":  func() error { _, err := st.ListCertificates("service"); return err },
		"delete certificate": func() error { return st.DeleteCertificate("certificate") },
		"upsert API schema":  func() error { _, err := st.UpsertAPISchema(model.APISchema{}); return err },
		"get API schema":     func() error { _, err := st.GetAPISchema("schema"); return err },
		"list API schemas":   func() error { _, err := st.ListAPISchemas("api"); return err },
		"delete API schema":  func() error { return st.DeleteAPISchema("schema") },
		"upsert tag":         func() error { _, err := st.UpsertTag(model.Tag{}); return err },
		"get tag":            func() error { _, err := st.GetTag("tag"); return err },
		"list tags":          func() error { _, err := st.ListTags("service"); return err },
		"delete tag":         func() error { return st.DeleteTag("tag") },
		"assign tag":         func() error { return st.AssignTag("resource", "tag") },
		"detach tag":         func() error { return st.DetachTag("resource", "tag") },
		"get resource tag": func() error {
			_, err := st.GetResourceTag("resource", "tag")
			return err
		},
		"list resource tags": func() error { _, err := st.ListResourceTags("resource"); return err },
		"upsert group":       func() error { _, err := st.UpsertGroup(model.Group{}); return err },
		"get group":          func() error { _, err := st.GetGroup("group"); return err },
		"list groups":        func() error { _, err := st.ListGroups("service"); return err },
		"delete group":       func() error { return st.DeleteGroup("group") },
		"link product group": func() error { return st.LinkProductGroup("product", "group") },
		"unlink product group": func() error {
			return st.UnlinkProductGroup("product", "group")
		},
		"has product group": func() error { _, err := st.HasProductGroup("product", "group"); return err },
		"list product groups": func() error {
			_, err := st.ListProductGroups("product")
			return err
		},
		"upsert user":       func() error { _, err := st.UpsertUser(model.User{}); return err },
		"get user":          func() error { _, err := st.GetUser("user"); return err },
		"list users":        func() error { _, err := st.ListUsers("service"); return err },
		"delete user":       func() error { return st.DeleteUser("user") },
		"link group user":   func() error { return st.LinkGroupUser("group", "user") },
		"unlink group user": func() error { return st.UnlinkGroupUser("group", "user") },
		"has group user":    func() error { _, err := st.HasGroupUser("group", "user"); return err },
		"list group users":  func() error { _, err := st.ListGroupUsers("group"); return err },
		"list user groups":  func() error { _, err := st.ListUserGroups("user"); return err },
		"upsert policy fragment": func() error {
			_, err := st.UpsertPolicyFragment(model.PolicyFragment{})
			return err
		},
		"get policy fragment": func() error { _, err := st.GetPolicyFragment("fragment"); return err },
		"list policy fragments": func() error {
			_, err := st.ListPolicyFragments("service")
			return err
		},
		"delete policy fragment": func() error { return st.DeletePolicyFragment("fragment") },
		"list fragment references": func() error {
			_, err := st.ListPolicyFragmentReferences("service", "fragment")
			return err
		},
		"upsert logger": func() error { _, err := st.UpsertLogger(model.Logger{}); return err },
		"get logger":    func() error { _, err := st.GetLogger("logger"); return err },
		"list loggers":  func() error { _, err := st.ListLoggers("service"); return err },
		"delete logger": func() error { return st.DeleteLogger("logger") },
		"upsert diagnostic": func() error {
			_, err := st.UpsertDiagnostic(model.Diagnostic{})
			return err
		},
		"get diagnostic":   func() error { _, err := st.GetDiagnostic("diagnostic"); return err },
		"list diagnostics": func() error { _, err := st.ListDiagnostics("service"); return err },
		"list service diagnostics": func() error {
			_, err := st.ListServiceDiagnostics("service")
			return err
		},
		"delete diagnostic": func() error { return st.DeleteDiagnostic("diagnostic") },
		"add diagnostic event": func() error {
			return st.AddDiagnosticEvent(model.DiagnosticEvent{})
		},
		"list diagnostic events": func() error {
			_, err := st.ListDiagnosticEvents("service")
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
			 CREATE TABLE api_documents (api_id, document_json);
			 CREATE TABLE api_revision_metadata (api_id, revision, description, is_current, created_at, updated_at);
			 CREATE TABLE api_version_metadata (api_id, version, version_set_id)`,
			`INSERT INTO apis VALUES ('id', NULL, '', '', '', '', '[]', 0, '')`,
			func(db *sql.DB) error { _, err := scanAPIs(db); return err },
		},
		{
			"version sets",
			`CREATE TABLE api_version_sets (id, service_id, name, display_name, versioning_scheme, version_header_name, version_query_name, description, etag);
			 CREATE TABLE api_version_set_documents (version_set_id, document_json)`,
			`INSERT INTO api_version_sets VALUES ('id', 'service', NULL, '', '', '', '', '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListAPIVersionSets("service"); return err },
		},
		{
			"named values",
			`CREATE TABLE named_values (id, service_id, name, display_name, value, tags_json, secret, key_vault_secret_id, key_vault_identity_id, etag)`,
			`INSERT INTO named_values VALUES ('id', 'service', NULL, '', '', '[]', 0, '', '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListNamedValues("service"); return err },
		},
		{
			"backends",
			`CREATE TABLE backends (id, service_id, name, title, description, url, protocol, resource_id, document_json, etag)`,
			`INSERT INTO backends VALUES ('id', 'service', NULL, '', '', '', '', '', '{}', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListBackends("service"); return err },
		},
		{
			"certificates",
			`CREATE TABLE certificates (id, service_id, name, subject, thumbprint, expiration, data, password, key_vault_secret_id, key_vault_identity_id, etag)`,
			`INSERT INTO certificates VALUES ('id', 'service', NULL, '', '', 0, x'', '', '', '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListCertificates("service"); return err },
		},
		{
			"releases",
			`CREATE TABLE api_releases (id, api_id, name, target_api_id, notes, created_at, updated_at, etag);
			 CREATE TABLE api_release_documents (release_id, document_json)`,
			`INSERT INTO api_releases VALUES ('id', 'id', NULL, '', '', 0, 0, '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListAPIReleases("id"); return err },
		},
		{
			"operations",
			`CREATE TABLE operations (id, api_id, name, display_name, method, url_template, etag);
			 CREATE TABLE operation_documents (operation_id, document_json)`,
			`INSERT INTO operations VALUES ('id', NULL, '', '', '', '', '')`,
			func(db *sql.DB) error { _, err := scanOperations(db); return err },
		},
		{
			"API schemas",
			`CREATE TABLE api_schemas (id, api_id, name, content_type, document_json, etag)`,
			`INSERT INTO api_schemas VALUES ('id', 'api', NULL, '', '{}', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListAPISchemas("api"); return err },
		},
		{
			"tags",
			`CREATE TABLE tags (id, service_id, name, display_name, etag);
			 CREATE TABLE tag_documents (tag_id, document_json)`,
			`INSERT INTO tags VALUES ('tag', 'service', NULL, '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListTags("service"); return err },
		},
		{
			"resource tags",
			`CREATE TABLE tags (id, service_id, name, display_name, etag);
			 CREATE TABLE tag_documents (tag_id, document_json);
			 CREATE TABLE resource_tags (resource_id, tag_id)`,
			`INSERT INTO tags VALUES ('tag', 'service', NULL, '', '');
			 INSERT INTO resource_tags VALUES ('resource', 'tag')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListResourceTags("resource"); return err },
		},
		{
			"groups",
			`CREATE TABLE groups (id, service_id, name, display_name, description, type, external_id, built_in, etag);
			 CREATE TABLE group_documents (group_id, document_json)`,
			`INSERT INTO groups VALUES ('group', 'service', NULL, '', '', '', '', 0, '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListGroups("service"); return err },
		},
		{
			"product groups",
			`CREATE TABLE groups (id, service_id, name, display_name, description, type, external_id, built_in, etag);
			 CREATE TABLE group_documents (group_id, document_json);
			 CREATE TABLE product_groups (product_id, group_id)`,
			`INSERT INTO groups VALUES ('group', 'service', NULL, '', '', '', '', 0, '');
			 INSERT INTO product_groups VALUES ('product', 'group')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListProductGroups("product"); return err },
		},
		{
			"users",
			`CREATE TABLE users (id, service_id, name, first_name, last_name, email, state, note, identities_json, registration_at, password, primary_key, secondary_key, etag);
			 CREATE TABLE user_documents (user_id, document_json)`,
			`INSERT INTO users VALUES ('user', 'service', NULL, '', '', '', '', '', '[]', 0, '', '', '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListUsers("service"); return err },
		},
		{
			"group users",
			`CREATE TABLE users (id, service_id, name, first_name, last_name, email, state, note, identities_json, registration_at, password, primary_key, secondary_key, etag);
			 CREATE TABLE user_documents (user_id, document_json);
			 CREATE TABLE group_users (group_id, user_id)`,
			`INSERT INTO users VALUES ('user', 'service', NULL, '', '', '', '', '', '[]', 0, '', '', '', '');
			 INSERT INTO group_users VALUES ('group', 'user')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListGroupUsers("group"); return err },
		},
		{
			"policy fragments",
			`CREATE TABLE policy_fragments (id, service_id, name, description, format, value, provisioning_state, etag);
			 CREATE TABLE policy_fragment_documents (fragment_id, document_json)`,
			`INSERT INTO policy_fragments VALUES ('fragment', 'service', NULL, '', '', '', '', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListPolicyFragments("service"); return err },
		},
		{
			"policy fragment references",
			`CREATE TABLE policies (scope_id, format, value, etag)`,
			`INSERT INTO policies VALUES ('service/api', NULL, '<include-fragment fragment-id="fragment"/>', '')`,
			func(db *sql.DB) error {
				_, err := (&Store{db: db}).ListPolicyFragmentReferences("service", "fragment")
				return err
			},
		},
		{
			"loggers",
			`CREATE TABLE loggers (id, service_id, name, logger_type, description, is_buffered, resource_id, credentials_json, document_json, etag)`,
			`INSERT INTO loggers VALUES ('id', 'service', NULL, '', '', 0, '', '{}', '{}', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListLoggers("service"); return err },
		},
		{
			"diagnostics",
			`CREATE TABLE diagnostics (id, service_id, scope_id, name, logger_id, always_log, log_client_ip, verbosity, sampling_type, sampling_percentage, document_json, etag)`,
			`INSERT INTO diagnostics VALUES ('id', 'service', 'scope', NULL, '', '', 0, '', '', 0, '{}', '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListDiagnostics("scope"); return err },
		},
		{
			"diagnostic events",
			`CREATE TABLE diagnostic_events (id, service_id, api_id, diagnostic_id, correlation_id, method, path, status_code, timestamp, duration_nanos, client_ip)`,
			`INSERT INTO diagnostic_events VALUES ('id', 'service', NULL, '', '', '', '', 0, 0, 0, '')`,
			func(db *sql.DB) error { _, err := (&Store{db: db}).ListDiagnosticEvents("service"); return err },
		},
		{
			"products",
			`CREATE TABLE products (id, service_id, name, display_name, state, approval_required, etag);
			 CREATE TABLE product_documents (product_id, document_json)`,
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
			`CREATE TABLE subscriptions (id, service_id, name, display_name, scope, state, primary_key, secondary_key, etag);
			 CREATE TABLE subscription_documents (subscription_id, document_json)`,
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

func TestUpsertSubscriptionTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertSubscription(model.Subscription{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("subscription accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertSubscription(model.Subscription{}); err == nil {
			t.Fatal("closed store accepted a subscription")
		}
	})
	t.Run("subscription row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertSubscription(model.Subscription{ServiceID: "/missing", Name: "subscription"}); err == nil {
			t.Fatal("subscription with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_subscription_document BEFORE INSERT ON subscription_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		subscription := model.Subscription{ServiceID: service.ID(), Name: "subscription"}
		if _, err := st.UpsertSubscription(subscription); err == nil {
			t.Fatal("rejected subscription document was accepted")
		}
		if _, err := st.GetSubscription(subscription.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("subscription transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertUserTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertUser(model.User{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("user accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertUser(model.User{}); err == nil {
			t.Fatal("closed store accepted a user")
		}
	})
	t.Run("user row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertUser(model.User{ServiceID: "/missing", Name: "user"}); err == nil {
			t.Fatal("user with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_user_document BEFORE INSERT ON user_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		user := model.User{ServiceID: service.ID(), Name: "user"}
		if _, err := st.UpsertUser(user); err == nil {
			t.Fatal("rejected user document was accepted")
		}
		if _, err := st.GetUser(user.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("user transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertPolicyFragmentTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertPolicyFragment(model.PolicyFragment{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("policy fragment accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertPolicyFragment(model.PolicyFragment{}); err == nil {
			t.Fatal("closed store accepted a policy fragment")
		}
	})
	t.Run("fragment row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertPolicyFragment(model.PolicyFragment{ServiceID: "/missing", Name: "fragment"}); err == nil {
			t.Fatal("policy fragment with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_fragment_document BEFORE INSERT ON policy_fragment_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		fragment := model.PolicyFragment{ServiceID: service.ID(), Name: "fragment"}
		if _, err := st.UpsertPolicyFragment(fragment); err == nil {
			t.Fatal("rejected policy-fragment document was accepted")
		}
		if _, err := st.GetPolicyFragment(fragment.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("policy-fragment transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertTagTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertTag(model.Tag{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("tag accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertTag(model.Tag{}); err == nil {
			t.Fatal("closed store accepted a tag")
		}
	})
	t.Run("tag row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertTag(model.Tag{ServiceID: "/missing", Name: "tag"}); err == nil {
			t.Fatal("tag with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_tag_document BEFORE INSERT ON tag_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		tag := model.Tag{ServiceID: service.ID(), Name: "tag"}
		if _, err := st.UpsertTag(tag); err == nil {
			t.Fatal("rejected tag document was accepted")
		}
		if _, err := st.GetTag(tag.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("tag transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertAPIVersionSetTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertAPIVersionSet(model.APIVersionSet{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("version set accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertAPIVersionSet(model.APIVersionSet{}); err == nil {
			t.Fatal("closed store accepted a version set")
		}
	})
	t.Run("version set row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertAPIVersionSet(model.APIVersionSet{ServiceID: "/missing", Name: "versions"}); err == nil {
			t.Fatal("version set with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_version_set_document BEFORE INSERT ON api_version_set_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		versionSet := model.APIVersionSet{ServiceID: service.ID(), Name: "versions"}
		if _, err := st.UpsertAPIVersionSet(versionSet); err == nil {
			t.Fatal("rejected version-set document was accepted")
		}
		if _, err := st.GetAPIVersionSet(versionSet.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("version-set transaction was not rolled back: %v", err)
		}
	})
}

func TestUpsertGroupTransactionErrors(t *testing.T) {
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertGroup(model.Group{Document: map[string]any{"bad": make(chan int)}}); err == nil {
			t.Fatal("group accepted an unsupported document")
		}
	})
	t.Run("begin", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Close()
		if _, err := st.UpsertGroup(model.Group{}); err == nil {
			t.Fatal("closed store accepted a group")
		}
	})
	t.Run("group row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.UpsertGroup(model.Group{ServiceID: "/missing", Name: "group"}); err == nil {
			t.Fatal("group with a missing service was accepted")
		}
	})
	t.Run("document row", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, _ := st.UpsertService(model.Service{Name: "svc"})
		if _, err := st.db.Exec(`CREATE TRIGGER reject_group_document BEFORE INSERT ON group_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		group := model.Group{ServiceID: service.ID(), Name: "group"}
		if _, err := st.UpsertGroup(group); err == nil {
			t.Fatal("rejected group document was accepted")
		}
		if _, err := st.GetGroup(group.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("group transaction was not rolled back: %v", err)
		}
	})
}

func TestTagAssociations(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	tag := model.Tag{ServiceID: service.ID(), Name: "public", DisplayName: "Public"}
	tag, err = st.UpsertTag(tag)
	if err != nil || tag.ETag == "" {
		t.Fatalf("UpsertTag = %+v, %v", tag, err)
	}
	updated, err := st.UpsertTag(model.Tag{ServiceID: service.ID(), Name: "public", DisplayName: "Updated"})
	if err != nil || updated.DisplayName != "Updated" || updated.ETag == tag.ETag {
		t.Fatalf("updated tag = %+v, %v", updated, err)
	}
	got, err := st.GetTag(strings.ToUpper(tag.ID()))
	if err != nil || got.DisplayName != "Updated" {
		t.Fatalf("GetTag = %+v, %v", got, err)
	}
	if _, err := st.GetTag("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tag = %v", err)
	}
	values, err := st.ListTags(strings.ToUpper(service.ID()))
	if err != nil || len(values) != 1 {
		t.Fatalf("ListTags = %+v, %v", values, err)
	}

	resourceID := service.ID() + "/apis/api"
	if err := st.AssignTag(resourceID, tag.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.AssignTag(resourceID, tag.ID()); err != nil {
		t.Fatalf("repeated AssignTag = %v", err)
	}
	got, err = st.GetResourceTag(strings.ToUpper(resourceID), strings.ToUpper(tag.ID()))
	if err != nil || got.Name != tag.Name {
		t.Fatalf("GetResourceTag = %+v, %v", got, err)
	}
	values, err = st.ListResourceTags(strings.ToUpper(resourceID))
	if err != nil || len(values) != 1 {
		t.Fatalf("ListResourceTags = %+v, %v", values, err)
	}
	if _, err := st.GetResourceTag(resourceID, "/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing resource tag = %v", err)
	}
	if err := st.DetachTag(resourceID, tag.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DetachTag(resourceID, tag.ID()); err != nil {
		t.Fatalf("repeated DetachTag = %v", err)
	}
	if err := st.AssignTag(resourceID, tag.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTag(tag.ID()); err != nil {
		t.Fatal(err)
	}
	if values, err := st.ListResourceTags(resourceID); err != nil || len(values) != 0 {
		t.Fatalf("associations survived tag deletion: %+v, %v", values, err)
	}
	if err := st.DeleteTag(tag.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second tag delete = %v", err)
	}
}

func TestGroupAndProductAssociations(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := st.ListGroups(strings.ToUpper(service.ID()))
	if err != nil || len(groups) != 3 || !groups[0].BuiltIn || groups[0].Type != "system" {
		t.Fatalf("built-in groups = %+v, %v", groups, err)
	}
	group := model.Group{ServiceID: service.ID(), Name: "partners", DisplayName: "Partners", Description: "External partners", Type: "custom"}
	group, err = st.UpsertGroup(group)
	if err != nil || group.ETag == "" {
		t.Fatalf("UpsertGroup = %+v, %v", group, err)
	}
	updated, err := st.UpsertGroup(model.Group{ServiceID: service.ID(), Name: group.Name, DisplayName: "Updated", Type: "external", ExternalID: "aad://group"})
	if err != nil || updated.DisplayName != "Updated" || updated.ETag == group.ETag {
		t.Fatalf("updated group = %+v, %v", updated, err)
	}
	got, err := st.GetGroup(strings.ToUpper(group.ID()))
	if err != nil || got.ExternalID != "aad://group" {
		t.Fatalf("GetGroup = %+v, %v", got, err)
	}
	if _, err := st.GetGroup("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing group = %v", err)
	}
	product, err := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "product", DisplayName: "Product"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatalf("repeated LinkProductGroup = %v", err)
	}
	if exists, err := st.HasProductGroup(strings.ToUpper(product.ID()), strings.ToUpper(group.ID())); err != nil || !exists {
		t.Fatalf("HasProductGroup = %v, %v", exists, err)
	}
	if exists, err := st.HasProductGroup(product.ID(), "/missing"); err != nil || exists {
		t.Fatalf("missing product group = %v, %v", exists, err)
	}
	groups, err = st.ListProductGroups(strings.ToUpper(product.ID()))
	if err != nil || len(groups) != 1 || groups[0].Name != group.Name {
		t.Fatalf("ListProductGroups = %+v, %v", groups, err)
	}
	if err := st.UnlinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.UnlinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatalf("repeated UnlinkProductGroup = %v", err)
	}
	if err := st.LinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteGroup(group.ID()); err != nil {
		t.Fatal(err)
	}
	if groups, err := st.ListProductGroups(product.ID()); err != nil || len(groups) != 0 {
		t.Fatalf("product link survived group deletion: %+v, %v", groups, err)
	}
	if err := st.DeleteGroup(group.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second group delete = %v", err)
	}
}

func TestUserAndGroupMemberships(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	group, err := st.UpsertGroup(model.Group{ServiceID: service.ID(), Name: "partners", DisplayName: "Partners", Type: "custom"})
	if err != nil {
		t.Fatal(err)
	}
	user := model.User{ServiceID: service.ID(), Name: "calvin", FirstName: "Calvin", LastName: "Cheng", Email: "calvin@example.test", State: "active", Identities: []model.UserIdentity{{Provider: "Azure", ID: "object"}}, Document: map[string]any{"password": "root", "primaryKey": "root-key", "secondaryKey": "root-key-2", "custom": true, "properties": map[string]any{"password": "nested", "primaryKey": "nested-key", "secondaryKey": "nested-key-2"}}}
	user, err = st.UpsertUser(user)
	if err != nil || user.ETag == "" || user.RegistrationAt == 0 || user.Password == "" || user.PrimaryKey == "" || user.SecondaryKey == "" || user.Document["password"] != nil || user.Document["custom"] != true {
		t.Fatalf("UpsertUser = %+v, %v", user, err)
	}
	updated := user
	updated.FirstName, updated.Note = "Updated", "note"
	updated, err = st.UpsertUser(updated)
	if err != nil || updated.FirstName != "Updated" || updated.RegistrationAt != user.RegistrationAt || updated.PrimaryKey != user.PrimaryKey {
		t.Fatalf("updated user = %+v, %v", updated, err)
	}
	got, err := st.GetUser(strings.ToUpper(user.ID()))
	if err != nil || len(got.Identities) != 1 || got.Identities[0].ID != "object" || got.Document["password"] != nil || got.Document["properties"].(map[string]any)["primaryKey"] != nil {
		t.Fatalf("GetUser = %+v, %v", got, err)
	}
	if _, err := st.GetUser("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user = %v", err)
	}
	if users, err := st.ListUsers(strings.ToUpper(service.ID())); err != nil || len(users) != 1 {
		t.Fatalf("ListUsers = %+v, %v", users, err)
	}
	duplicate := model.User{ServiceID: service.ID(), Name: "duplicate", FirstName: "D", LastName: "U", Email: strings.ToUpper(user.Email), State: "active"}
	if _, err := st.UpsertUser(duplicate); err == nil {
		t.Fatal("duplicate email was accepted")
	}
	if err := st.LinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatalf("repeated link = %v", err)
	}
	if exists, err := st.HasGroupUser(strings.ToUpper(group.ID()), strings.ToUpper(user.ID())); err != nil || !exists {
		t.Fatalf("membership = %v, %v", exists, err)
	}
	if exists, err := st.HasGroupUser(group.ID(), "/missing"); err != nil || exists {
		t.Fatalf("missing membership = %v, %v", exists, err)
	}
	if users, err := st.ListGroupUsers(group.ID()); err != nil || len(users) != 1 {
		t.Fatalf("group users = %+v, %v", users, err)
	}
	if groups, err := st.ListUserGroups(user.ID()); err != nil || len(groups) != 1 || groups[0].Name != group.Name {
		t.Fatalf("user groups = %+v, %v", groups, err)
	}
	if err := st.UnlinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.UnlinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatalf("repeated unlink = %v", err)
	}
	if err := st.LinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(user.ID()); err != nil {
		t.Fatal(err)
	}
	if users, err := st.ListGroupUsers(group.ID()); err != nil || len(users) != 0 {
		t.Fatalf("membership survived user deletion: %+v, %v", users, err)
	}
	if err := st.DeleteUser(user.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestPolicyFragmentLifecycleAndReferences(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	fragment := model.PolicyFragment{ServiceID: service.ID(), Name: "headers", Description: "Headers", Value: `<fragment/>`}
	fragment, err = st.UpsertPolicyFragment(fragment)
	if err != nil || fragment.Format != "xml" || fragment.ProvisioningState != "Succeeded" || fragment.ETag == "" {
		t.Fatalf("fragment = %+v, %v", fragment, err)
	}
	updated, err := st.UpsertPolicyFragment(model.PolicyFragment{ServiceID: service.ID(), Name: fragment.Name, Description: "Updated", Format: "rawxml", Value: `<fragment><base/></fragment>`})
	if err != nil || updated.Description != "Updated" || updated.ETag == fragment.ETag {
		t.Fatalf("updated fragment = %+v, %v", updated, err)
	}
	got, err := st.GetPolicyFragment(strings.ToUpper(fragment.ID()))
	if err != nil || got.Format != "rawxml" {
		t.Fatalf("GetPolicyFragment = %+v, %v", got, err)
	}
	if _, err := st.GetPolicyFragment("/missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing fragment = %v", err)
	}
	if values, err := st.ListPolicyFragments(strings.ToUpper(service.ID())); err != nil || len(values) != 1 {
		t.Fatalf("ListPolicyFragments = %+v, %v", values, err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound><include-fragment fragment-id='HEADERS'/></inbound></policies>`}); err != nil {
		t.Fatal(err)
	}
	if refs, err := st.ListPolicyFragmentReferences(strings.ToUpper(service.ID()), "headers"); err != nil || len(refs) != 1 || refs[0].ScopeID != api.ID() {
		t.Fatalf("fragment references = %+v, %v", refs, err)
	}
	if refs, err := st.ListPolicyFragmentReferences(service.ID(), "missing"); err != nil || len(refs) != 0 {
		t.Fatalf("missing references = %+v, %v", refs, err)
	}
	if err := st.DeletePolicyFragment(fragment.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePolicyFragment(fragment.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
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

	t.Run("API document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		api := model.API{Name: "bad", Document: map[string]any{"unsupported": func() {}}}
		if _, err := st.UpsertAPI(api); err == nil {
			t.Fatal("unsupported API document was accepted")
		}
	})

	t.Run("built-in groups", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if _, err := st.db.Exec(`CREATE TRIGGER reject_builtin_group BEFORE INSERT ON groups BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		service := model.Service{Name: "bad"}
		if _, err := st.UpsertService(service); err == nil {
			t.Fatal("rejected built-in group was accepted")
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

	t.Run("document", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, err := st.UpsertService(model.Service{Name: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.db.Exec(`CREATE TRIGGER reject_api_document BEFORE INSERT ON api_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
			t.Fatal(err)
		}
		api := model.API{ServiceID: service.ID(), Name: "api", Document: map[string]any{"custom": true}}
		if _, err := st.UpsertAPI(api); err == nil {
			t.Fatal("rejected API document was accepted")
		}
		if _, err := st.GetAPI(api.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("API document transaction was not rolled back: %v", err)
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
		operation, err := st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "get", Method: "GET", URLTemplate: "/"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: "<policies/>"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "schema", ContentType: "application/json", Document: map[string]any{"components": map[string]any{"Example": map[string]any{"type": "string"}}}}); err != nil {
			t.Fatal(err)
		}
		tag, err := st.UpsertTag(model.Tag{ServiceID: service.ID(), Name: "public", DisplayName: "Public"})
		if err != nil {
			t.Fatal(err)
		}
		for _, resourceID := range []string{api.ID(), operation.APIID + "/operations/" + operation.Name} {
			if err := st.AssignTag(resourceID, tag.ID()); err != nil {
				t.Fatal(err)
			}
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
		if schemas, err := st.ListAPISchemas(cloned.ID()); err != nil || len(schemas) != 1 {
			t.Fatalf("cloned schemas = %+v, %v", schemas, err)
		}
		if tags, err := st.ListResourceTags(cloned.ID()); err != nil || len(tags) != 1 {
			t.Fatalf("cloned API tags = %+v, %v", tags, err)
		}
		if tags, err := st.ListResourceTags(cloned.ID() + "/operations/get"); err != nil || len(tags) != 1 {
			t.Fatalf("cloned operation tags = %+v, %v", tags, err)
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

	t.Run("document encoding", func(t *testing.T) {
		st, source := newSource(t)
		target := source
		target.Name = "api;rev=2"
		target.Document = map[string]any{"bad": make(chan int)}
		if _, err := st.CloneAPIRevision(source.ID(), target); err == nil {
			t.Fatal("clone accepted an unsupported API document")
		}
	})

	for _, test := range []struct{ name, trigger string }{
		{"document", `CREATE TRIGGER reject_clone_document BEFORE INSERT ON api_documents WHEN NEW.api_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"metadata", `CREATE TRIGGER reject_clone_metadata BEFORE INSERT ON api_revision_metadata WHEN NEW.revision='2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"version metadata", `CREATE TRIGGER reject_clone_version BEFORE INSERT ON api_version_metadata WHEN NEW.api_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"operations", `CREATE TRIGGER reject_clone_operation BEFORE INSERT ON operations WHEN NEW.api_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"operation documents", `CREATE TRIGGER reject_clone_operation_document BEFORE INSERT ON operation_documents WHEN NEW.operation_id LIKE '%;rev=2%' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"schemas", `CREATE TRIGGER reject_clone_schema BEFORE INSERT ON api_schemas WHEN NEW.api_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"policy", `CREATE TRIGGER reject_clone_policy BEFORE INSERT ON policies WHEN NEW.scope_id LIKE '%;rev=2' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
		{"tags", `CREATE TRIGGER reject_clone_tag BEFORE INSERT ON resource_tags WHEN NEW.resource_id LIKE '%;rev=2%' BEGIN SELECT RAISE(FAIL, 'rejected'); END`},
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
		{"document encoding", func(t *testing.T, st *Store, release model.APIRelease) {
			release.Document = map[string]any{"bad": make(chan int)}
			if _, err := st.UpsertAPIRelease(release); err == nil {
				t.Fatal("unsupported release document was accepted")
			}
		}},
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
		{"document write", func(t *testing.T, st *Store, release model.APIRelease) {
			_, _ = st.db.Exec(`CREATE TRIGGER reject_release_document BEFORE INSERT ON api_release_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`)
			if _, err := st.UpsertAPIRelease(release); err == nil {
				t.Fatal("document write error ignored")
			}
			if _, err := st.GetAPIRelease(release.ID()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("release transaction was not rolled back: %v", err)
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

func TestNamedValueLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "named-values"})
	if err != nil {
		t.Fatal(err)
	}
	value, err := st.UpsertNamedValue(model.NamedValue{ServiceID: service.ID(), Name: "token", DisplayName: "Token", Value: "secret", Tags: []string{"auth"}, Secret: true})
	if err != nil || value.ID() != service.ID()+"/namedValues/token" || value.ETag == "" {
		t.Fatalf("upsert named value = %+v, %v", value, err)
	}
	got, err := st.GetNamedValue(strings.ToUpper(value.ID()))
	if err != nil || got.Value != "secret" || len(got.Tags) != 1 || !got.Secret {
		t.Fatalf("get named value = %+v, %v", got, err)
	}
	values, err := st.ListNamedValues(service.ID())
	if err != nil || len(values) != 1 {
		t.Fatalf("list named values = %+v, %v", values, err)
	}
	if _, err := st.UpsertNamedValue(model.NamedValue{ServiceID: service.ID(), Name: "duplicate", DisplayName: "TOKEN", Value: "duplicate"}); err == nil {
		t.Fatal("duplicate named-value display name should fail")
	}
	if err := st.DeleteNamedValue(value.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetNamedValue(value.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing named value error = %v", err)
	}
	if err := st.DeleteNamedValue(value.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete error = %v", err)
	}
}

func TestBackendLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "backends"})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := st.UpsertBackend(model.Backend{ServiceID: service.ID(), Name: "primary", Title: "Primary", URL: "https://backend", Protocol: "http", Document: map[string]any{"properties": map[string]any{"credentials": map[string]any{"header": map[string]any{"X-Key": []any{"secret"}}}}}})
	if err != nil || backend.ID() != service.ID()+"/backends/primary" || backend.ETag == "" {
		t.Fatalf("backend = %+v, %v", backend, err)
	}
	got, err := st.GetBackend(strings.ToUpper(backend.ID()))
	if err != nil || got.Title != "Primary" || got.Document["properties"] == nil {
		t.Fatalf("get backend = %+v, %v", got, err)
	}
	values, err := st.ListBackends(service.ID())
	if err != nil || len(values) != 1 {
		t.Fatalf("list backends = %+v, %v", values, err)
	}
	if err := st.DeleteBackend(backend.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetBackend(backend.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing backend = %v", err)
	}
	if err := st.DeleteBackend(backend.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestCertificateLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "certificates"})
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Unix(4102444800, 0).UTC()
	certificate, err := st.UpsertCertificate(model.Certificate{ServiceID: service.ID(), Name: "client", Subject: "CN=client", Thumbprint: "ABC", Expiration: expires, Data: []byte("pfx"), Password: "secret"})
	if err != nil || certificate.ID() != service.ID()+"/certificates/client" || certificate.ETag == "" {
		t.Fatalf("certificate = %+v, %v", certificate, err)
	}
	got, err := st.GetCertificate(strings.ToUpper(certificate.ID()))
	if err != nil || got.Subject != "CN=client" || !got.Expiration.Equal(expires) || string(got.Data) != "pfx" {
		t.Fatalf("get certificate = %+v, %v", got, err)
	}
	values, err := st.ListCertificates(service.ID())
	if err != nil || len(values) != 1 || !values[0].Expiration.Equal(expires) {
		t.Fatalf("list certificates = %+v, %v", values, err)
	}
	keyVault, err := st.UpsertCertificate(model.Certificate{ServiceID: service.ID(), Name: "vault", KeyVaultSecretID: "https://vault/secret"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetCertificate(keyVault.ID()); err != nil || !got.Expiration.IsZero() {
		t.Fatalf("key vault certificate = %+v, %v", got, err)
	}
	if err := st.DeleteCertificate(certificate.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetCertificate(certificate.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing certificate = %v", err)
	}
	if err := st.DeleteCertificate(certificate.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestLoggerDiagnosticAndEventLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api", DisplayName: "API"})
	if err != nil {
		t.Fatal(err)
	}
	logger, err := st.UpsertLogger(model.Logger{ServiceID: service.ID(), Name: "app", LoggerType: "applicationInsights", IsBuffered: true, Credentials: map[string]string{"instrumentationKey": "secret"}, Document: map[string]any{"properties": map[string]any{"custom": true}}})
	if err != nil || logger.ETag == "" {
		t.Fatalf("UpsertLogger = %+v, %v", logger, err)
	}
	logger.Description = "updated"
	if logger, err = st.UpsertLogger(logger); err != nil || logger.Description != "updated" {
		t.Fatalf("update logger = %+v, %v", logger, err)
	}
	gotLogger, err := st.GetLogger(strings.ToUpper(logger.ID()))
	if err != nil || gotLogger.Credentials["instrumentationKey"] != "secret" || gotLogger.Document["properties"].(map[string]any)["custom"] != true {
		t.Fatalf("GetLogger = %+v, %v", gotLogger, err)
	}
	if values, err := st.ListLoggers(strings.ToUpper(service.ID())); err != nil || len(values) != 1 {
		t.Fatalf("ListLoggers = %+v, %v", values, err)
	}
	if _, err := st.GetLogger("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing logger = %v", err)
	}

	diagnostic, err := st.UpsertDiagnostic(model.Diagnostic{ServiceID: service.ID(), ScopeID: api.ID(), Name: "app", LoggerID: logger.ID(), AlwaysLog: "allErrors", LogClientIP: true, Verbosity: "information", SamplingType: "fixed", SamplingPercentage: 50, Document: map[string]any{"properties": map[string]any{"frontend": map[string]any{"request": map[string]any{"body": map[string]any{"bytes": 64.0}}}}}})
	if err != nil || diagnostic.ETag == "" {
		t.Fatalf("UpsertDiagnostic = %+v, %v", diagnostic, err)
	}
	diagnostic.Verbosity = "verbose"
	if diagnostic, err = st.UpsertDiagnostic(diagnostic); err != nil || diagnostic.Verbosity != "verbose" {
		t.Fatalf("update diagnostic = %+v, %v", diagnostic, err)
	}
	gotDiagnostic, err := st.GetDiagnostic(strings.ToUpper(diagnostic.ID()))
	if err != nil || gotDiagnostic.SamplingPercentage != 50 || gotDiagnostic.Document == nil {
		t.Fatalf("GetDiagnostic = %+v, %v", gotDiagnostic, err)
	}
	if values, err := st.ListDiagnostics(strings.ToUpper(api.ID())); err != nil || len(values) != 1 {
		t.Fatalf("ListDiagnostics = %+v, %v", values, err)
	}
	if values, err := st.ListServiceDiagnostics(strings.ToUpper(service.ID())); err != nil || len(values) != 1 {
		t.Fatalf("ListServiceDiagnostics = %+v, %v", values, err)
	}
	if _, err := st.GetDiagnostic("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing diagnostic = %v", err)
	}
	if err := st.DeleteLogger(logger.ID()); !errors.Is(err, ErrConflict) {
		t.Fatalf("referenced logger delete = %v", err)
	}

	event := model.DiagnosticEvent{ID: "event", ServiceID: service.ID(), APIID: api.ID(), DiagnosticID: diagnostic.ID(), CorrelationID: "correlation", Method: "GET", Path: "/api", StatusCode: 200, Timestamp: 123, DurationNanos: 456, ClientIP: "127.0.0.1"}
	if err := st.AddDiagnosticEvent(event); err != nil {
		t.Fatal(err)
	}
	if events, err := st.ListDiagnosticEvents(strings.ToUpper(service.ID())); err != nil || len(events) != 1 || events[0] != event {
		t.Fatalf("ListDiagnosticEvents = %+v, %v", events, err)
	}

	clone, err := st.CloneAPIRevision(api.ID(), model.API{ServiceID: service.ID(), Name: "api;rev=2", DisplayName: "API"})
	if err != nil {
		t.Fatal(err)
	}
	if values, err := st.ListDiagnostics(clone.ID()); err != nil || len(values) != 1 || values[0].LoggerID != logger.ID() {
		t.Fatalf("cloned diagnostics = %+v, %v", values, err)
	}
	if err := st.DeleteAPI(clone.ID()); err != nil {
		t.Fatal(err)
	}
	if values, err := st.ListDiagnostics(clone.ID()); err != nil || len(values) != 0 {
		t.Fatalf("deleted API diagnostics = %+v, %v", values, err)
	}
	if err := st.DeleteDiagnostic(diagnostic.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDiagnostic(diagnostic.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second diagnostic delete = %v", err)
	}
	if err := st.DeleteLogger(logger.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteLogger(logger.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second logger delete = %v", err)
	}
}

func TestLoggerDiagnosticJSONFailures(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bad := make(chan int)
	if _, err := st.UpsertLogger(model.Logger{Credentials: map[string]string{}, Document: map[string]any{"bad": bad}}); err == nil {
		t.Fatal("logger document marshal succeeded after credentials")
	}
	if _, err := st.UpsertDiagnostic(model.Diagnostic{Document: map[string]any{"bad": bad}}); err == nil {
		t.Fatal("diagnostic document marshal succeeded")
	}
	if _, err := st.db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO loggers VALUES ('logger', 'service', 'name', 'azureMonitor', '', 1, '', '{', '{}', '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListLoggers("service"); err == nil {
		t.Fatal("malformed logger credentials accepted")
	}
	if _, err := st.db.Exec(`UPDATE loggers SET credentials_json='{}', document_json='{'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListLoggers("service"); err == nil {
		t.Fatal("malformed logger document accepted")
	}
	if _, err := st.db.Exec(`INSERT INTO diagnostics VALUES ('diagnostic', 'service', 'scope', 'name', 'logger', '', 0, '', 'fixed', 100, '{', '')`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListDiagnostics("scope"); err == nil {
		t.Fatal("malformed diagnostic document accepted")
	}
}

func TestDiagnosticTransactionFailures(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
	logger, _ := st.UpsertLogger(model.Logger{ServiceID: service.ID(), Name: "logger"})
	_, _ = st.UpsertDiagnostic(model.Diagnostic{ServiceID: service.ID(), ScopeID: api.ID(), Name: "d", LoggerID: logger.ID()})
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_diagnostic_clone BEFORE INSERT ON diagnostics BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CloneAPIRevision(api.ID(), model.API{ServiceID: service.ID(), Name: "api;rev=2"}); err == nil {
		t.Fatal("diagnostic clone trigger was ignored")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_diagnostic_clone; CREATE TRIGGER reject_diagnostic_delete BEFORE DELETE ON diagnostics BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAPI(api.ID()); err == nil {
		t.Fatal("diagnostic cleanup trigger was ignored")
	}
}

func TestImportedAPILifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	api := model.API{ServiceID: service.ID(), Name: "imported", DisplayName: "Imported", Path: "/api/", ServiceURL: "https://backend", Protocols: []string{"https"}}
	definition := model.APIDefinition{Format: "openapi+json", Value: `{}`, SourceURL: "https://source"}
	operations := []model.Operation{{Name: "get", DisplayName: "Get", Method: "get", URLTemplate: "/items"}}
	schema := &model.APISchema{ContentType: "application/json", Document: map[string]any{"components": map[string]any{"Item": map[string]any{"type": "object"}}}}
	api, err = st.ImportAPI(api, definition, operations, schema)
	if err != nil || api.ETag == "" || api.Revision != "1" || !api.IsCurrent || api.CreatedAt == 0 {
		t.Fatalf("ImportAPI = %+v, %v", api, err)
	}
	gotDefinition, err := st.GetAPIDefinition(strings.ToUpper(api.ID()))
	if err != nil || gotDefinition.Format != definition.Format || gotDefinition.Value != definition.Value || gotDefinition.ETag == "" {
		t.Fatalf("GetAPIDefinition = %+v, %v", gotDefinition, err)
	}
	if _, err := st.GetAPIDefinition("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing definition = %v", err)
	}
	if values, err := st.ListOperations(api.ID()); err != nil || len(values) != 1 || values[0].Method != "GET" {
		t.Fatalf("operations = %+v, %v", values, err)
	}
	if values, err := st.ListAPISchemas(api.ID()); err != nil || len(values) != 1 || values[0].Name != "openapi" {
		t.Fatalf("schemas = %+v, %v", values, err)
	}
	clone, err := st.CloneAPIRevision(api.ID(), model.API{ServiceID: service.ID(), Name: "imported;rev=2", DisplayName: "Imported", ServiceURL: "https://backend"})
	if err != nil {
		t.Fatal(err)
	}
	if clonedDefinition, err := st.GetAPIDefinition(clone.ID()); err != nil || clonedDefinition.Value != definition.Value {
		t.Fatalf("cloned definition = %+v, %v", clonedDefinition, err)
	}
	created := api.CreatedAt
	api.Revision = "1"
	api.CreatedAt = created
	api, err = st.ImportAPI(api, model.APIDefinition{Format: "openapi", Value: "updated"}, nil, nil)
	if err != nil || api.CreatedAt != created {
		t.Fatalf("updated import = %+v, %v", api, err)
	}
	if values, _ := st.ListOperations(api.ID()); len(values) != 0 {
		t.Fatalf("operations not replaced = %+v", values)
	}
	if values, _ := st.ListAPISchemas(api.ID()); len(values) != 0 {
		t.Fatalf("schema not replaced = %+v", values)
	}
	other, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "other"})
	versionSet, _ := st.UpsertAPIVersionSet(model.APIVersionSet{ServiceID: other.ID(), Name: "versions"})
	if _, err := st.ImportAPI(model.API{ServiceID: service.ID(), Name: "bad", Version: "v1", VersionSetID: versionSet.ID()}, definition, nil, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("foreign version set = %v", err)
	}
	if _, err := st.ImportAPI(model.API{ServiceID: service.ID(), Name: "bad-schema"}, definition, nil, &model.APISchema{Document: map[string]any{"bad": make(chan int)}}); err == nil {
		t.Fatal("unencodable schema imported")
	}
}

func TestCloneAPIDefinitionFailure(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
	api, _ := st.ImportAPI(model.API{ServiceID: service.ID(), Name: "api"}, model.APIDefinition{Value: "source"}, nil, nil)
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER reject_definition_clone BEFORE INSERT ON api_definitions BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CloneAPIRevision(api.ID(), model.API{ServiceID: service.ID(), Name: "api;rev=2"}); err == nil {
		t.Fatal("definition clone trigger was ignored")
	}
}

func TestImportAPITransactionFailures(t *testing.T) {
	tests := []struct {
		name, trigger string
		operations    []model.Operation
		schema        *model.APISchema
	}{
		{"api", `CREATE TRIGGER reject BEFORE INSERT ON apis BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"document", `CREATE TRIGGER reject BEFORE UPDATE ON api_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"revision", `CREATE TRIGGER reject BEFORE INSERT ON api_revision_metadata BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"version", `CREATE TRIGGER reject BEFORE INSERT ON api_version_metadata BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"definition", `CREATE TRIGGER reject BEFORE INSERT ON api_definitions BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"operation delete", `CREATE TRIGGER reject BEFORE DELETE ON operations BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"operation insert", `CREATE TRIGGER reject BEFORE INSERT ON operations BEGIN SELECT RAISE(FAIL, 'rejected'); END`, []model.Operation{{Name: "new"}}, nil},
		{"operation document", `CREATE TRIGGER reject BEFORE INSERT ON operation_documents BEGIN SELECT RAISE(FAIL, 'rejected'); END`, []model.Operation{{Name: "new"}}, nil},
		{"schema delete", `CREATE TRIGGER reject BEFORE DELETE ON api_schemas BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, nil},
		{"schema insert", `CREATE TRIGGER reject BEFORE INSERT ON api_schemas BEGIN SELECT RAISE(FAIL, 'rejected'); END`, nil, &model.APISchema{Document: map[string]any{}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			st, err := Open(dir, clock.New())
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc"})
			api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
			_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "old"})
			_, _ = st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "openapi", ContentType: "application/json", Document: map[string]any{}})
			db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(test.trigger); err != nil {
				t.Fatal(err)
			}
			if _, err := st.ImportAPI(api, model.APIDefinition{}, test.operations, test.schema); err == nil {
				t.Fatal("triggered import succeeded")
			}
		})
	}
	t.Run("document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		api := model.API{Document: map[string]any{"bad": make(chan int)}}
		if _, err := st.ImportAPI(api, model.APIDefinition{}, nil, nil); err == nil {
			t.Fatal("import accepted an unsupported API document")
		}
	})
	t.Run("operation document encoding", func(t *testing.T) {
		st, err := Open("", clock.New())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		service, err := st.UpsertService(model.Service{Name: "svc"})
		if err != nil {
			t.Fatal(err)
		}
		api := model.API{ServiceID: service.ID(), Name: "api"}
		operations := []model.Operation{{Name: "get", Document: map[string]any{"bad": make(chan int)}}}
		if _, err := st.ImportAPI(api, model.APIDefinition{}, operations, nil); err == nil {
			t.Fatal("import accepted an unsupported operation document")
		}
	})
}

func TestAPISchemaLifecycle(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{Name: "schemas"})
	if err != nil {
		t.Fatal(err)
	}
	api, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := st.UpsertAPISchema(model.APISchema{APIID: api.ID(), Name: "payload", ContentType: "application/json", Document: map[string]any{"definitions": map[string]any{"Item": map[string]any{"type": "object"}}}})
	if err != nil || schema.ID() != api.ID()+"/schemas/payload" || schema.ETag == "" {
		t.Fatalf("schema = %+v, %v", schema, err)
	}
	got, err := st.GetAPISchema(strings.ToUpper(schema.ID()))
	if err != nil || got.ContentType != "application/json" || got.Document["definitions"] == nil {
		t.Fatalf("get schema = %+v, %v", got, err)
	}
	values, err := st.ListAPISchemas(api.ID())
	if err != nil || len(values) != 1 {
		t.Fatalf("list schemas = %+v, %v", values, err)
	}
	if err := st.DeleteAPISchema(schema.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAPISchema(schema.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing schema = %v", err)
	}
	if err := st.DeleteAPISchema(schema.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
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
