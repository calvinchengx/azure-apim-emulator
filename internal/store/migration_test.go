package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
)

// A database created before workspaces existed must come forward without losing
// data, and must then accept workspace-scoped resources.
func TestLegacyDatabaseAdoptsScopes(t *testing.T) {
	dir := t.TempDir()
	// Build a LEGACY database by hand: the old parent, no scopes table.
	legacy, err := openDB("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE services (id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL, resource_group TEXT NOT NULL,
  name TEXT NOT NULL, location TEXT NOT NULL, sku_name TEXT NOT NULL, sku_capacity INTEGER NOT NULL,
  publisher_name TEXT NOT NULL, publisher_email TEXT NOT NULL, provisioning_state TEXT NOT NULL, etag TEXT NOT NULL);
CREATE TABLE apis (id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL, display_name TEXT NOT NULL, path TEXT NOT NULL, service_url TEXT NOT NULL,
  protocols_json TEXT NOT NULL, subscription_required INTEGER NOT NULL, etag TEXT NOT NULL);
INSERT INTO services VALUES ('/s/svc','sub','rg','svc','local','Developer',1,'L','l@x.test','Succeeded','e1');
INSERT INTO apis VALUES ('/s/svc/apis/legacy','/s/svc','legacy','Legacy','p','https://b','[]',0,'e2');
`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	st, err := Open(dir, clock.New())
	if err != nil {
		t.Fatalf("opening a legacy database must migrate it, got %v", err)
	}
	defer st.Close()

	// Nothing lost.
	apis, err := st.ListAPIs("/s/svc")
	if err != nil {
		t.Fatal(err)
	}
	if len(apis) != 1 || apis[0].Name != "legacy" {
		t.Fatalf("the legacy API must survive the rebuild, got %+v", apis)
	}
	// And the parent is now a scope, so a workspace-scoped resource inserts.
	if _, err := st.UpsertWorkspace(model.Workspace{ServiceID: "/s/svc", Name: "team", DisplayName: "Team"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAPI(model.API{ServiceID: "/s/svc/workspaces/team", Name: "ws", DisplayName: "WS", Path: "w"}); err != nil {
		t.Fatalf("a workspace-scoped API must insert after migration: %v", err)
	}
	scoped, err := st.ListAPIs("/s/svc/workspaces/team")
	if err != nil || len(scoped) != 1 {
		t.Fatalf("workspace listing = %v %v", scoped, err)
	}
	if again, _ := st.ListAPIs("/s/svc"); len(again) != 1 {
		t.Fatalf("the workspace API must not leak into the service listing, got %d", len(again))
	}
	// Re-opening an already-migrated database must be a no-op, not a rebuild.
	st.Close()
	reopened, err := Open(dir, clock.New())
	if err != nil {
		t.Fatalf("re-open after migration: %v", err)
	}
	defer reopened.Close()
	if apis, err := reopened.ListAPIs("/s/svc"); err != nil || len(apis) != 1 {
		t.Fatalf("re-open lost data: %v %v", apis, err)
	}
}

// Deleting a workspace takes everything parented to it, and nothing else.
func TestDeleteWorkspaceCascades(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertWorkspace(model.Workspace{ServiceID: service.ID(), Name: "team", DisplayName: "Team"}); err != nil {
		t.Fatal(err)
	}
	workspaceScope := service.ID() + "/workspaces/team"
	if _, err := st.UpsertAPI(model.API{ServiceID: workspaceScope, Name: "ws", DisplayName: "WS", Path: "w"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAPI(model.API{ServiceID: service.ID(), Name: "svc", DisplayName: "SVC", Path: "s"}); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListWorkspaces(service.ID()); len(list) != 1 {
		t.Fatalf("ListWorkspaces = %v", list)
	}
	if _, err := st.GetWorkspace(workspaceScope); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteWorkspace(workspaceScope); err != nil {
		t.Fatal(err)
	}
	if apis, _ := st.ListAPIs(workspaceScope); len(apis) != 0 {
		t.Fatalf("the workspace's APIs must go with it, got %v", apis)
	}
	if apis, _ := st.ListAPIs(service.ID()); len(apis) != 1 {
		t.Fatalf("the service's own APIs must survive, got %v", apis)
	}
	if err := st.DeleteWorkspace(workspaceScope); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting an absent workspace = %v, want ErrNotFound", err)
	}

	// And deleting the SERVICE takes its workspaces' scopes too, so nothing is
	// left addressable at a scope whose owner is gone.
	if _, err := st.UpsertWorkspace(model.Workspace{ServiceID: service.ID(), Name: "team2", DisplayName: "T2"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteService(service.ID()); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListWorkspaces(service.ID()); len(list) != 0 {
		t.Fatalf("deleting a service must take its workspaces, got %v", list)
	}
}

// The migration's own failure paths. A store that cannot be read must report
// it rather than leave a half-rebuilt schema behind.
func TestAdoptScopesReportsFailures(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := st.adoptScopes(); err == nil {
		t.Fatal("a closed database must be reported")
	}
	if _, err := st.scopeRebuildScript(); err == nil {
		t.Fatal("a closed database must be reported when reading the schema")
	}
}

// A rebuild that cannot complete leaves the original tables intact, because the
// whole script is one transaction.
func TestAdoptScopesIsAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	legacy, err := openDB("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	// A legacy table whose rebuild cannot succeed: the name the migration needs
	// for its scratch copy is already taken.
	if _, err := legacy.Exec(`
CREATE TABLE services (id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL, resource_group TEXT NOT NULL,
  name TEXT NOT NULL, location TEXT NOT NULL, sku_name TEXT NOT NULL, sku_capacity INTEGER NOT NULL,
  publisher_name TEXT NOT NULL, publisher_email TEXT NOT NULL, provisioning_state TEXT NOT NULL, etag TEXT NOT NULL);
CREATE TABLE broken (id TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE);
CREATE TABLE broken_scoped (occupied TEXT);
INSERT INTO services VALUES ('/s/svc','sub','rg','svc','local','Developer',1,'L','l@x.test','Succeeded','e1');
`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	if _, err := Open(dir, clock.New()); err == nil {
		t.Fatal("a migration that cannot complete must fail the open, not leave a half-rebuilt schema")
	}

	// The original table is still there and still named what it was.
	check, err := openDB("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var name string
	if err := check.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='broken'`).Scan(&name); err != nil {
		t.Fatalf("the original table must survive a failed migration: %v", err)
	}
	// The table still has its original shape: still parented to services, not
	// half-rebuilt.
	var sql string
	if err := check.QueryRow(`SELECT sql FROM sqlite_master WHERE name='broken'`).Scan(&sql); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "REFERENCES services(id)") {
		t.Fatalf("a failed migration must leave the original definition intact, got %s", sql)
	}
}

// A document that cannot be encoded is reported rather than stored as something
// else. Unreachable from ARM, which only stores decoded JSON.
func TestUpsertWorkspaceRejectsUnencodableDocuments(t *testing.T) {
	st, err := Open("", clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UpsertWorkspace(model.Workspace{
		ServiceID: "/s/svc", Name: "team", DisplayName: "Team",
		Document: map[string]any{"bad": make(chan int)},
	}); err == nil {
		t.Fatal("an unencodable document must be reported")
	}
}

// The second statement in each transaction, forced to fail with a trigger the
// way the repo tests its other multi-table writes. Both must roll back rather
// than leave a row whose scope was never registered, or a scope with no owner.
func TestScopeRegistrationRollsBack(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	service, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "svc", Location: "local"})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// A service whose scope cannot be registered must not be stored: every
	// resource table hangs off that scope, so the service would be unusable.
	if _, err := db.Exec(`CREATE TRIGGER reject_scope BEFORE INSERT ON scopes BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertService(model.Service{SubscriptionID: "sub", ResourceGroup: "rg", Name: "second", Location: "local"}); err == nil {
		t.Fatal("a service whose scope cannot be registered must fail")
	}
	if _, err := st.UpsertWorkspace(model.Workspace{ServiceID: service.ID(), Name: "team", DisplayName: "Team"}); err == nil {
		t.Fatal("a workspace whose scope cannot be registered must fail")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_scope`); err != nil {
		t.Fatal(err)
	}

	// And the other order: the scope registers but the workspace row does not.
	if _, err := db.Exec(`CREATE TRIGGER reject_workspace BEFORE INSERT ON workspaces BEGIN SELECT RAISE(FAIL, 'rejected'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertWorkspace(model.Workspace{ServiceID: service.ID(), Name: "team", DisplayName: "Team"}); err == nil {
		t.Fatal("a workspace row that cannot be written must fail the whole write")
	}
	if _, err := db.Exec(`DROP TRIGGER reject_workspace`); err != nil {
		t.Fatal(err)
	}
	// The rolled-back scope must be gone, not left orphaned.
	var orphans int
	if err := db.QueryRow(`SELECT count(*) FROM scopes WHERE id = ?`, service.ID()+"/workspaces/team").Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Fatalf("a failed workspace write left %d orphaned scopes", orphans)
	}
}
