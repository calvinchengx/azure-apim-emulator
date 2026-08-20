package arm

import (
	"crypto/hmac"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/auth"
	"github.com/calvinchengx/azure-apim-emulator/internal/clock"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const gatewayBody = `{"properties":{"locationData":{"name":"contoso-dc","city":"Wellington","countryOrRegion":"NZ"},"description":"edge of the lab"}}`

func gatewayPath(name string) string { return basePath + "/gateways/" + name + apiQuery }
func gatewayAction(a string) string  { return basePath + "/gateways/edge/" + a + apiQuery }
func gatewayHostname(n string) string {
	return basePath + "/gateways/edge/hostnameConfigurations/" + n + apiQuery
}

func seedGateway(t *testing.T, handler *Handler) {
	t.Helper()
	assertStatus(t, handler, http.MethodPut, gatewayPath("edge"), gatewayBody, http.StatusCreated)
}

func TestGatewayLifecycle(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	collection := basePath + "/gateways" + apiQuery
	seedGateway(t, handler)

	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodOptions, gatewayPath("edge"), "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPut, gatewayPath("edge"), `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodHead, gatewayPath("edge"), "", http.StatusOK)

	got := request(t, handler, http.MethodGet, gatewayPath("edge"), "")
	// The whole locationData object survives, not just the name the emulator
	// keeps a column for: a gateway records where an operator ran it, and the
	// city and country are part of that answer.
	if !strings.Contains(got.Body.String(), `"city":"Wellington"`) || !strings.Contains(got.Body.String(), `"name":"contoso-dc"`) {
		t.Fatalf("gateway GET = %s", got.Body.String())
	}

	// A gateway records where it runs; without that it describes nothing.
	assertStatus(t, handler, http.MethodPut, gatewayPath("bare"), `{"properties":{"description":"nowhere"}}`, http.StatusBadRequest)

	// `managed` names the service's own built-in gateway.
	assertStatus(t, handler, http.MethodPut, gatewayPath("managed"), gatewayBody, http.StatusBadRequest)

	assertStatus(t, handler, http.MethodPatch, gatewayPath("edge"), `{"properties":{"description":"renamed"}}`, http.StatusOK)
	if body := request(t, handler, http.MethodGet, gatewayPath("edge"), "").Body.String(); !strings.Contains(body, "renamed") {
		t.Fatalf("PATCH = %s", body)
	}
	// A description cleared back to empty disappears rather than reporting "".
	assertStatus(t, handler, http.MethodPatch, gatewayPath("edge"), `{"properties":{"description":""}}`, http.StatusOK)
	if body := request(t, handler, http.MethodGet, gatewayPath("edge"), "").Body.String(); strings.Contains(body, `"description"`) {
		t.Fatalf("cleared description survived: %s", body)
	}
	assertStatus(t, handler, http.MethodPatch, gatewayPath("absent"), `{"properties":{}}`, http.StatusNotFound)

	assertStatus(t, handler, http.MethodDelete, gatewayPath("edge"), "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodGet, gatewayPath("edge"), "", http.StatusNotFound)
	// Deleting a gateway requires If-Match, so a second delete fails the
	// precondition rather than reporting success: the entity tag it is
	// conditioned on no longer exists.
	assertStatus(t, handler, http.MethodDelete, gatewayPath("edge"), "", http.StatusPreconditionFailed)
}

// A gateway needs a service to belong to, and a missing one is a 404 rather
// than the conflict the foreign key would otherwise produce.
func TestGatewayRequiresService(t *testing.T) {
	handler, _ := testHandler(t)
	assertStatus(t, handler, http.MethodPut, gatewayPath("edge"), gatewayBody, http.StatusNotFound)
}

// Azure has no service/{svc}/workspaces/{ws}/gateways. Serving that path at
// service scope would accept a URL Azure answers 404 to, and put the resource
// in a scope the caller never named.
func TestGatewayIsNotWorkspaceScoped(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	if _, err := st.UpsertWorkspace(model.Workspace{ServiceID: serviceModel().ID(), Name: "team", DisplayName: "Team"}); err != nil {
		t.Fatal(err)
	}
	workspaceGateway := basePath + "/workspaces/team/gateways/edge" + apiQuery
	assertStatus(t, handler, http.MethodPut, workspaceGateway, gatewayBody, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/workspaces/team/gateways"+apiQuery, "", http.StatusNotFound)
}

func TestGatewayKeysAndToken(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)

	// A GET must never carry the keys: listKeys is the only way to read them,
	// exactly as with a subscription.
	if body := request(t, handler, http.MethodGet, gatewayPath("edge"), "").Body.String(); strings.Contains(body, "primaryKey") {
		t.Fatalf("a key leaked through GET: %s", body)
	}
	keys := request(t, handler, http.MethodPost, gatewayAction("listKeys"), "")
	var issued struct{ Primary, Secondary string }
	if err := json.Unmarshal(keys.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Primary == "" || issued.Secondary == "" || issued.Primary == issued.Secondary {
		t.Fatalf("listKeys = %s", keys.Body.String())
	}
	assertStatus(t, handler, http.MethodGet, gatewayAction("listKeys"), "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, gatewayAction("unknownAction"), "", http.StatusNotFound)
	// These exist in Azure and are not implemented here. A 404 would claim the
	// operation does not exist, which is a different and wrong statement.
	assertStatus(t, handler, http.MethodPost, gatewayAction("listTrace"), `{"traceId":"t"}`, http.StatusNotImplemented)
	assertStatus(t, handler, http.MethodPost, gatewayAction("listDebugCredentials"), `{"purposes":["tracing"],"apiId":"a"}`, http.StatusNotImplemented)
	assertStatus(t, handler, http.MethodPost, gatewayAction("invalidateDebugCredentials"), "", http.StatusNotImplemented)

	expiry := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	token := request(t, handler, http.MethodPost, gatewayAction("generateToken"),
		`{"keyType":"primary","expiry":"`+expiry+`"}`)
	var minted struct{ Value string }
	if err := json.Unmarshal(token.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(minted.Value, "&")
	if len(parts) != 3 || parts[0] != "edge" {
		t.Fatalf("token = %q", minted.Value)
	}
	// Recomputed rather than compared to a fixture, so the test asserts the
	// signature relation and not a string this code happened to produce.
	mac := hmac.New(sha512.New, []byte(issued.Primary))
	mac.Write([]byte("edge\n" + parts[1]))
	if parts[2] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature mismatch for %q", minted.Value)
	}
	if stamp, err := time.Parse(tokenExpiryLayout, parts[1]); err != nil || stamp.Format(time.RFC3339) != expiry {
		t.Fatalf("token expiry %q does not restate %q: %v", parts[1], expiry, err)
	}

	// The secondary key signs a different token, which is the entire reason
	// there are two: a rotation must not invalidate what the other key signed.
	secondary := request(t, handler, http.MethodPost, gatewayAction("generateToken"),
		`{"keyType":"secondary","expiry":"`+expiry+`"}`)
	if strings.Contains(secondary.Body.String(), parts[2]) {
		t.Fatalf("both keys signed the same token: %s", secondary.Body.String())
	}

	assertStatus(t, handler, http.MethodPost, gatewayAction("generateToken"), `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, gatewayAction("generateToken"), `{"keyType":"tertiary","expiry":"`+expiry+`"}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, gatewayAction("generateToken"), `{"keyType":"primary","expiry":"whenever"}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, gatewayAction("generateToken"),
		`{"keyType":"primary","expiry":"`+time.Now().UTC().Add(400*24*time.Hour).Format(time.RFC3339)+`"}`, http.StatusBadRequest)
}

func TestGatewayKeyRegeneration(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)
	before := request(t, handler, http.MethodPost, gatewayAction("listKeys"), "").Body.String()

	assertStatus(t, handler, http.MethodPost, gatewayAction("regenerateKey"), `{"keyType":"primary"}`, http.StatusNoContent)
	assertStatus(t, handler, http.MethodPost, gatewayAction("regenerateKey"), `{"keyType":"secondary"}`, http.StatusNoContent)
	assertStatus(t, handler, http.MethodPost, gatewayAction("regenerateKey"), `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPost, gatewayAction("regenerateKey"), `{"keyType":"tertiary"}`, http.StatusBadRequest)

	if after := request(t, handler, http.MethodPost, gatewayAction("listKeys"), "").Body.String(); after == before {
		t.Fatalf("regeneration left the keys unchanged: %s", after)
	}
}

// An ordinary update must not reissue the keys: that would revoke every token
// already minted from the old pair, which is a change nobody asked for.
func TestGatewayUpdateKeepsIssuedKeys(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)
	before := request(t, handler, http.MethodPost, gatewayAction("listKeys"), "").Body.String()
	assertStatus(t, handler, http.MethodPut, gatewayPath("edge"), gatewayBody, http.StatusOK)
	if after := request(t, handler, http.MethodPost, gatewayAction("listKeys"), "").Body.String(); after != before {
		t.Fatalf("an update reissued the keys: %s then %s", before, after)
	}
}

func TestGatewayAPIAssociations(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)
	if _, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "echo", DisplayName: "Echo", Path: "echo", ServiceURL: "https://backend.test"}); err != nil {
		t.Fatal(err)
	}
	link := basePath + "/gateways/edge/apis/echo" + apiQuery
	collection := basePath + "/gateways/edge/apis" + apiQuery

	// An association with an API nobody defined would put a route on the
	// gateway that resolves to nothing, discovered only by calling it.
	assertStatus(t, handler, http.MethodPut, basePath+"/gateways/edge/apis/absent"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodHead, link, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPut, link, "", http.StatusCreated)
	assertStatus(t, handler, http.MethodHead, link, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, link, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)

	if body := request(t, handler, http.MethodGet, collection, "").Body.String(); !strings.Contains(body, `"Echo"`) {
		t.Fatalf("the association list must carry the API itself: %s", body)
	}
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusNoContent)
	// Deleting a link that was never made is a 404, not a success.
	assertStatus(t, handler, http.MethodDelete, link, "", http.StatusNotFound)

	// Everything under a gateway needs the gateway to exist first, otherwise a
	// typo associates an API with a gateway nobody registered.
	assertStatus(t, handler, http.MethodPut, basePath+"/gateways/absent/apis/echo"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/gateways/edge/apis/echo/extra"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, basePath+"/gateways/edge/unknownChild/x"+apiQuery, "", http.StatusNotFound)
}

// The association list reports the APIs themselves, so an API deleted out from
// under a live link is a failure the caller sees rather than a silent gap.
func TestGatewayAPIListReportsMissingAPI(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)
	if err := st.AttachGatewayAPI(serviceModel().ID()+"/gateways/edge", serviceModel().ID()+"/apis/ghost"); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, basePath+"/gateways/edge/apis"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodHead, basePath+"/gateways/edge/apis/ghost"+apiQuery, "", http.StatusNotFound)
}

func TestGatewayHostnameConfigurations(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)
	collection := basePath + "/gateways/edge/hostnameConfigurations" + apiQuery

	assertStatus(t, handler, http.MethodPut, gatewayHostname("primary"),
		`{"properties":{"hostname":"edge.example.test","http2Enabled":true,"tls10Enabled":false,"tls11Enabled":false,"negotiateClientCertificate":true}}`,
		http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, gatewayHostname("primary"), "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodHead, gatewayHostname("primary"), "", http.StatusOK)
	assertStatus(t, handler, http.MethodPut, gatewayHostname("primary"), `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPut, gatewayHostname("bare"), `{"properties":{}}`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodPatch, gatewayHostname("absent"), `{"properties":{}}`, http.StatusNotFound)
	assertStatus(t, handler, http.MethodGet, gatewayHostname("absent"), "", http.StatusNotFound)

	if body := request(t, handler, http.MethodGet, gatewayHostname("primary"), "").Body.String(); !strings.Contains(body, `"http2Enabled":true`) {
		t.Fatalf("hostname GET = %s", body)
	}
	assertStatus(t, handler, http.MethodPatch, gatewayHostname("primary"), `{"properties":{"tls11Enabled":true}}`, http.StatusOK)

	// certificateId names a certificate entity on the same service. A hostname
	// pointing at one nobody uploaded would present no chain at all, so the
	// reference is refused here rather than at the first TLS handshake.
	assertStatus(t, handler, http.MethodPut, gatewayHostname("secure"),
		`{"properties":{"hostname":"secure.example.test","certificateId":"missing"}}`, http.StatusNotFound)
	if _, err := st.UpsertCertificate(model.Certificate{ServiceID: serviceModel().ID(), Name: "edge-cert"}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, gatewayHostname("secure"),
		`{"properties":{"hostname":"secure.example.test","certificateId":"edge-cert"}}`, http.StatusCreated)
	// The portal and the SDK samples both write a full ARM ID here, so both
	// spellings have to resolve to the same certificate.
	assertStatus(t, handler, http.MethodPut, gatewayHostname("secure"),
		`{"properties":{"hostname":"secure.example.test","certificateId":"`+serviceModel().ID()+`/certificates/edge-cert"}}`, http.StatusOK)

	assertStatus(t, handler, http.MethodDelete, gatewayHostname("primary"), "", http.StatusNoContent)
	// Deleting a hostname configuration requires If-Match, so repeating the
	// delete fails the precondition rather than reporting success.
	assertStatus(t, handler, http.MethodDelete, gatewayHostname("primary"), "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodGet, basePath+"/gateways/edge/hostnameConfigurations/a/b"+apiQuery, "", http.StatusNotFound)
}

func TestGatewayCertificateAuthorities(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	seedGateway(t, handler)
	collection := basePath + "/gateways/edge/certificateAuthorities" + apiQuery
	path := basePath + "/gateways/edge/certificateAuthorities/root" + apiQuery

	assertStatus(t, handler, http.MethodPut, path, `{"properties":{"isTrusted":true}}`, http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, collection, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPost, collection, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodPost, path, "", http.StatusMethodNotAllowed)
	assertStatus(t, handler, http.MethodHead, path, "", http.StatusOK)
	assertStatus(t, handler, http.MethodPut, path, `{`, http.StatusBadRequest)
	assertStatus(t, handler, http.MethodGet, basePath+"/gateways/edge/certificateAuthorities/absent"+apiQuery, "", http.StatusNotFound)
	assertStatus(t, handler, http.MethodPatch, basePath+"/gateways/edge/certificateAuthorities/absent"+apiQuery, `{"properties":{}}`, http.StatusNotFound)

	if body := request(t, handler, http.MethodGet, path, "").Body.String(); !strings.Contains(body, `"isTrusted":true`) {
		t.Fatalf("certificate authority GET = %s", body)
	}
	// Withdrawing trust is a state change, not a deletion: the record stays and
	// says the authority is no longer trusted.
	assertStatus(t, handler, http.MethodPatch, path, `{"properties":{"isTrusted":false}}`, http.StatusOK)
	if body := request(t, handler, http.MethodGet, path, "").Body.String(); !strings.Contains(body, `"isTrusted":false`) {
		t.Fatalf("withdrawn trust = %s", body)
	}
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusNoContent)
	assertStatus(t, handler, http.MethodDelete, path, "", http.StatusPreconditionFailed)
	assertStatus(t, handler, http.MethodGet, basePath+"/gateways/edge/certificateAuthorities/a/b"+apiQuery, "", http.StatusNotFound)
}

// Every write that changes what a gateway serves has to republish the runtime
// snapshot. A registration that only landed in the store would leave the
// gateway's hostnames unroutable until something else happened to activate.
func TestGatewayWritesRepublishTheSnapshot(t *testing.T) {
	handler, st := testHandler(t)
	seedService(t, st)
	if _, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "echo", DisplayName: "Echo", Path: "echo", ServiceURL: "https://backend.test"}); err != nil {
		t.Fatal(err)
	}
	seedGateway(t, handler)
	failure := errors.New("activation refused")
	handler.Activate = func() error { return failure }

	for _, call := range []struct {
		method, path, body string
	}{
		{http.MethodPut, gatewayHostname("primary"), `{"properties":{"hostname":"edge.example.test"}}`},
		{http.MethodPut, basePath + "/gateways/edge/apis/echo" + apiQuery, ""},
		{http.MethodDelete, basePath + "/gateways/edge/apis/echo" + apiQuery, ""},
		{http.MethodDelete, gatewayHostname("primary"), ""},
		{http.MethodDelete, gatewayPath("edge"), ""},
	} {
		assertStatus(t, handler, call.method, call.path, call.body, http.StatusInternalServerError)
	}
}

// A store that refuses a write must be reported, not absorbed. Every gateway
// write is covered because each one leaves a different thing half-done if it
// silently reports success: an unregistered gateway, an association the runtime
// never learns about, a hostname nothing answers on.
func TestGatewayStoreErrorsAndWireFallbacks(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, clock.New())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	seedService(t, st)
	handler := &Handler{Store: st, Auth: auth.AllowAll{}}
	seedGateway(t, handler)
	if _, err := st.UpsertAPI(model.API{ServiceID: serviceModel().ID(), Name: "echo", DisplayName: "Echo", Path: "echo", ServiceURL: "https://backend.test"}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodPut, gatewayHostname("primary"), `{"properties":{"hostname":"edge.example.test"}}`, http.StatusCreated)
	authority := basePath + "/gateways/edge/certificateAuthorities/root" + apiQuery
	assertStatus(t, handler, http.MethodPut, authority, `{"properties":{"isTrusted":true}}`, http.StatusCreated)

	db, err := sql.Open("sqlite", filepath.Join(dir, "azure-apim-emulator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	for _, step := range []struct {
		setup              string
		method, path, body string
	}{
		{`CREATE TRIGGER reject_gateway_write BEFORE INSERT ON gateways BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodPut, gatewayPath("edge"), gatewayBody},
		{`DROP TRIGGER reject_gateway_write; CREATE TRIGGER reject_gateway_key BEFORE INSERT ON gateways BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodPost, gatewayAction("regenerateKey"), `{"keyType":"primary"}`},
		{`DROP TRIGGER reject_gateway_key; CREATE TRIGGER reject_gateway_link BEFORE INSERT ON gateway_apis BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodPut, basePath + "/gateways/edge/apis/echo" + apiQuery, ""},
		{`DROP TRIGGER reject_gateway_link; CREATE TRIGGER reject_gateway_host BEFORE INSERT ON gateway_hostname_configurations BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodPut, gatewayHostname("primary"), `{"properties":{"hostname":"edge.example.test"}}`},
		{`DROP TRIGGER reject_gateway_host; CREATE TRIGGER reject_gateway_host_delete BEFORE DELETE ON gateway_hostname_configurations BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodDelete, gatewayHostname("primary"), ""},
		{`DROP TRIGGER reject_gateway_host_delete; CREATE TRIGGER reject_gateway_ca BEFORE INSERT ON gateway_certificate_authorities BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodPut, authority, `{"properties":{"isTrusted":false}}`},
		{`DROP TRIGGER reject_gateway_ca; CREATE TRIGGER reject_gateway_ca_delete BEFORE DELETE ON gateway_certificate_authorities BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodDelete, authority, ""},
		{`DROP TRIGGER reject_gateway_ca_delete; CREATE TRIGGER reject_gateway_delete BEFORE DELETE ON gateways BEGIN SELECT RAISE(FAIL, 'rejected'); END`,
			http.MethodDelete, gatewayPath("edge"), ""},
	} {
		if _, err := db.Exec(step.setup); err != nil {
			t.Fatal(err)
		}
		assertStatus(t, handler, step.method, step.path, step.body, http.StatusConflict)
	}

	// The children go first, so the gateway itself still resolves and the
	// failure being reported is the child's own.
	if _, err := db.Exec(`DROP TRIGGER reject_gateway_delete; DROP TABLE gateway_hostname_configurations; DROP TABLE gateway_certificate_authorities; DROP TABLE gateway_apis`); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct{ method, path, body string }{
		{http.MethodGet, basePath + "/gateways/edge/apis" + apiQuery, ""},
		{http.MethodHead, basePath + "/gateways/edge/apis/echo" + apiQuery, ""},
		{http.MethodGet, basePath + "/gateways/edge/hostnameConfigurations" + apiQuery, ""},
		{http.MethodPut, gatewayHostname("primary"), `{"properties":{"hostname":"edge.example.test"}}`},
		{http.MethodGet, basePath + "/gateways/edge/certificateAuthorities" + apiQuery, ""},
		{http.MethodPut, authority, `{"properties":{"isTrusted":true}}`},
	} {
		assertStatus(t, handler, call.method, call.path, call.body, http.StatusConflict)
	}

	if _, err := db.Exec(`DROP TABLE gateways`); err != nil {
		t.Fatal(err)
	}
	for _, call := range []struct{ method, path, body string }{
		{http.MethodGet, basePath + "/gateways" + apiQuery, ""},
		{http.MethodGet, gatewayPath("edge"), ""},
		{http.MethodPut, gatewayPath("edge"), gatewayBody},
		{http.MethodDelete, gatewayPath("edge"), ""},
		{http.MethodPost, gatewayAction("listKeys"), ""},
	} {
		assertStatus(t, handler, call.method, call.path, call.body, http.StatusConflict)
	}

	// A stored document whose `properties` is not an object must not panic the
	// projection: the wire view rebuilds it rather than asserting on it.
	if got := gatewayWire(model.Gateway{ServiceID: "svc", Name: "edge", LocationName: "dc", Document: map[string]any{"properties": "scalar"}}); got["properties"].(map[string]any)["locationData"].(map[string]any)["name"] != "dc" {
		t.Fatalf("gateway wire fallback = %#v", got)
	}
	if got := gatewayHostnameWire(model.GatewayHostnameConfiguration{GatewayID: "gw", Name: "primary", Hostname: "edge.test", Document: map[string]any{"properties": "scalar"}}); got["properties"].(map[string]any)["hostname"] != "edge.test" {
		t.Fatalf("hostname wire fallback = %#v", got)
	}
	if got := gatewayCertificateAuthorityWire(model.GatewayCertificateAuthority{GatewayID: "gw", Name: "root", IsTrusted: true, Document: map[string]any{"properties": "scalar"}}); got["properties"].(map[string]any)["isTrusted"] != true {
		t.Fatalf("certificate authority wire fallback = %#v", got)
	}
}

func TestGatewayTokenLayoutIsFixedWidth(t *testing.T) {
	// .NET's `fffffff` always emits seven fractional digits. Go's `.9999999`
	// would trim the trailing zeros and sign a different string for the same
	// instant, so the layout is asserted on an instant whose fraction is zero.
	stamp := time.Date(2026, 8, 17, 1, 2, 3, 0, time.UTC)
	if got := gatewayToken("edge", stamp, "key"); !strings.HasPrefix(got, "edge&2026-08-17T01:02:03.0000000Z&") {
		t.Fatalf("token = %q", got)
	}
}

func TestCertificateReferenceAcceptsBothSpellings(t *testing.T) {
	serviceID := serviceModel().ID()
	if got := certificateReference(serviceID, "edge-cert"); got != serviceID+"/certificates/edge-cert" {
		t.Fatalf("bare name = %q", got)
	}
	if got := certificateReference(serviceID, "/subscriptions/other/certificates/edge-cert"); got != serviceID+"/certificates/edge-cert" {
		t.Fatalf("full ARM ID = %q", got)
	}
}

// The reserved name is checked before anything else, so it refuses even where
// the store would have accepted the write.
func TestGatewayNameReservedIsHandlerLevel(t *testing.T) {
	if !store.GatewayNameReserved("Managed") {
		t.Fatal("the built-in gateway name was not reserved")
	}
}
