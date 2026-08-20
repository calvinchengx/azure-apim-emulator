package gateway

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// The identity a policy can read: who called, which groups they are in, and
// what the product they came through grants. Driven end to end, because a
// member can be bound on the binder and still be empty through a real request
// -- which is exactly how four context members shipped hollow in #72.
func TestPolicyReadsTheCallersIdentity(t *testing.T) {
	st, err := store.Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "pets", DisplayName: "Pets", Path: "pets", ServiceURL: backend.URL, IsCurrent: true})
	_, _ = st.UpsertOperation(model.Operation{APIID: api.ID(), Name: "list", DisplayName: "List", Method: http.MethodGet, URLTemplate: "/"})

	user, err := st.UpsertUser(model.User{
		ServiceID: service.ID(), Name: "ada", FirstName: "Ada", LastName: "Lovelace",
		Email: "ada@example.test", Note: "vip", RegistrationAt: 1767225600,
		Identities: []model.UserIdentity{{Provider: "Basic", ID: "ada@example.test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	group, _ := st.UpsertGroup(model.Group{ServiceID: service.ID(), Name: "devs", DisplayName: "Developers"})
	if err := st.LinkGroupUser(group.ID(), user.ID()); err != nil {
		t.Fatal(err)
	}
	product, _ := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "starter", DisplayName: "Starter", State: "published"})
	if err := st.LinkProductAPI(product.ID(), api.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkProductGroup(product.ID(), group.ID()); err != nil {
		t.Fatal(err)
	}
	// The subscription names its owner the way ARM does, as a resource id.
	if _, err := st.UpsertSubscription(model.Subscription{
		ServiceID: service.ID(), Name: "dev", DisplayName: "Dev", Scope: product.ID(),
		State: "active", PrimaryKey: "the-key",
		Document: map[string]any{"properties": map[string]any{"ownerId": service.ID() + "/users/ada"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPolicy(model.Policy{ScopeID: api.ID(), Value: `<policies><inbound>` +
		`<set-header name="X-Email" exists-action="override"><value>@(context.User.Email)</value></set-header>` +
		`<set-header name="X-Name" exists-action="override"><value>@(context.User.FirstName + " " + context.User.LastName)</value></set-header>` +
		`<set-header name="X-Note" exists-action="override"><value>@(context.User.Note)</value></set-header>` +
		`<set-header name="X-Registered" exists-action="override"><value>@(context.User.RegistrationDate)</value></set-header>` +
		`<set-header name="X-Group" exists-action="override"><value>@(context.User.Groups[0].Name)</value></set-header>` +
		`<set-header name="X-Identity" exists-action="override"><value>@(context.User.Identities[0].Provider)</value></set-header>` +
		`<set-header name="X-ProductGroups" exists-action="override"><value>@(context.Product.Groups.Count.ToString())</value></set-header>` +
		`<set-header name="X-ProductApi" exists-action="override"><value>@(context.Product.Apis[0].Id)</value></set-header>` +
		`</inbound></policies>`}); err != nil {
		t.Fatal(err)
	}

	var seen http.Header
	runtime := New("emulator", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		seen = request.Header.Clone()
		return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	if err := runtime.Activate(st, true); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/pets", nil)
	request.Header.Set("Ocp-Apim-Subscription-Key", "the-key")
	recorder := httptest.NewRecorder()
	runtime.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d %s", recorder.Code, recorder.Body.String())
	}
	for header, want := range map[string]string{
		"X-Email":         "ada@example.test",
		"X-Name":          "Ada Lovelace",
		"X-Note":          "vip",
		"X-Group":         "Developers",
		"X-Identity":      "Basic",
		"X-ProductGroups": "1",
		"X-ProductApi":    "pets",
	} {
		if got := seen.Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	// The registration date is rendered, not empty: a user record carries it as
	// an epoch and a policy reads a timestamp.
	if !strings.HasPrefix(seen.Get("X-Registered"), "2026-") {
		t.Fatalf("X-Registered = %q", seen.Get("X-Registered"))
	}
}

// A subscription with no owner leaves context.User null rather than inventing
// an anonymous one, because `context.User != null` is a question a policy asks.
func TestUnownedSubscriptionLeavesTheUserNull(t *testing.T) {
	st, _ := store.Open("", clock.New())
	defer func() { _ = st.Close() }()
	service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
	for _, document := range []map[string]any{
		nil,
		{"properties": map[string]any{}},
		{"properties": map[string]any{"ownerId": "   "}},
		// An owner naming a user that does not exist is null too: reporting a
		// half-built user would be worse than reporting none.
		{"properties": map[string]any{"ownerId": service.ID() + "/users/ghost"}},
		// A bare name, with no resource path, still resolves by name.
		{"properties": map[string]any{"ownerId": "ghost"}},
	} {
		if got := subscriptionOwner(&Service{Users: nil}, model.Subscription{ServiceID: service.ID(), Document: document}); got != nil {
			t.Fatalf("owner for %v = %#v", document, got)
		}
	}
}

// Activation reports a store it cannot read rather than publishing a snapshot
// in which every caller silently has no identity.
func TestIdentityGraphLoadFailuresStopActivation(t *testing.T) {
	for _, table := range []string{"users", "group_users", "product_groups"} {
		t.Run(table, func(t *testing.T) {
			dir := t.TempDir()
			st, err := store.Open(dir, clock.New())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			service, _ := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "emulator", Location: "local"})
			user, _ := st.UpsertUser(model.User{ServiceID: service.ID(), Name: "ada", Email: "ada@example.test"})
			product, _ := st.UpsertProduct(model.Product{ServiceID: service.ID(), Name: "starter", DisplayName: "Starter"})
			group, _ := st.UpsertGroup(model.Group{ServiceID: service.ID(), Name: "devs", DisplayName: "Developers"})
			_ = st.LinkGroupUser(group.ID(), user.ID())
			_ = st.LinkProductGroup(product.ID(), group.ID())
			api, _ := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "pets", DisplayName: "Pets", Path: "pets", IsCurrent: true})
			_ = st.LinkProductAPI(product.ID(), api.ID())
			db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec("DROP TABLE " + table); err != nil {
				t.Fatal(err)
			}
			if err := New("emulator", nil).Activate(st, false); err == nil {
				t.Fatalf("activation succeeded with %s missing", table)
			}
		})
	}
}

// A service the snapshot never built is skipped rather than dereferenced.
func TestIdentityGraphSkipsAnAbsentService(t *testing.T) {
	st, _ := store.Open("", clock.New())
	defer func() { _ = st.Close() }()
	snapshot := &Snapshot{Services: map[string]*Service{}}
	if err := loadIdentityGraph(st, []model.Service{{SubscriptionID: "sub", ResourceGroup: "rg", Name: "absent"}}, nil, nil, snapshot); err != nil {
		t.Fatalf("an absent service failed the load: %v", err)
	}
}
