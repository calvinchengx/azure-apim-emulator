// Package inventory_test measures the emulator against the operation surface
// Microsoft publishes for the stable management API.
//
// WHAT THIS MEASURES, AND WHAT IT DOES NOT. It measures ROUTING: whether an
// operation is reachable at all. It does not measure whether the response is
// correct, and a routed operation is not a parity claim. The parity ledger
// grades behaviour; this grades existence, which is the weaker property that
// has to hold first.
//
// The reason it exists: every other number in `docs/parity.md` is a fraction of
// a surface we chose to describe. This is a fraction of the surface Azure
// publishes, so it is the only figure that can answer "how much is left".
package inventory_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/calvinchengx/azure-apim-emulator/pkg/emulator"
)

const apiVersion = "2024-05-01"

// Verdicts. Only two of these are conclusions; the third is an admission.
const (
	// verdictRouted means the emulator handled the path. Any response other
	// than 404 proves this, including a 400: rejecting a body requires having
	// parsed the route first. This is a LOWER BOUND on what exists.
	verdictRouted = "routed"
	// verdictAbsent means the emulator does not serve this operation, and the
	// 404 cannot be explained by a missing resource because everything the
	// path names was seeded (or, for PUT, is created by the call itself).
	verdictAbsent = "absent"
	// verdictUnmeasured means a 404 that this harness cannot attribute. The
	// operation hangs off a parent we could not seed, so "not implemented" and
	// "parent does not exist" are indistinguishable. Counting these either way
	// would be the whole point of the exercise thrown away.
	verdictUnmeasured = "unmeasured"
)

type operation struct {
	OperationID string            `json:"operationId"`
	Group       string            `json:"group"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	SpecFile    string            `json:"specFile"`
	PathEnums   map[string]string `json:"pathEnums"`
}

type inventoryDocument struct {
	APIVersion     string      `json:"apiVersion"`
	SpecCommit     string      `json:"specCommit"`
	OperationCount int         `json:"operationCount"`
	Operations     []operation `json:"operations"`
}

type result struct {
	OperationID string `json:"operationId"`
	Method      string `json:"method"`
	Verdict     string `json:"verdict"`
	Status      int    `json:"status"`
	// SetupStatus is the same-path PUT that tried to create what the operation
	// addresses. It is recorded because it is the evidence behind an
	// `unmeasured` verdict: it says whether we failed to create the resource,
	// and with which status, rather than leaving the reader to guess.
	SetupStatus int `json:"setupStatus,omitempty"`
}

type summary struct {
	Total      int `json:"total"`
	Routed     int `json:"routed"`
	Absent     int `json:"absent"`
	Unmeasured int `json:"unmeasured"`
}

type coverageDocument struct {
	Comment    []string       `json:"$comment"`
	APIVersion string         `json:"apiVersion"`
	SpecCommit string         `json:"specCommit"`
	Seeded     []string       `json:"seededParameters"`
	SeedFailed []string       `json:"seedFailures"`
	Summary    summary        `json:"summary"`
	ByGroup    map[string]sum `json:"byGroup"`
	Operations []result       `json:"operations"`
}

type sum struct {
	Routed     int `json:"routed"`
	Absent     int `json:"absent"`
	Unmeasured int `json:"unmeasured"`
}

var parameterPattern = regexp.MustCompile(`\{(\w+)\}`)

// seed is one resource created before probing, so that operations hanging off
// it become measurable. A seed that FAILS is not fatal: its children downgrade
// to `unmeasured`, which is the honest outcome. That is deliberate — a harness
// whose accuracy depends on every seed working would silently report absence
// the day a body shape changes.
type seed struct {
	parameter string
	name      string
	path      string
	body      string
}

func seeds() []seed {
	return []seed{
		{"workspaceId", "probe-workspace", "/workspaces/probe-workspace",
			`{"properties":{"displayName":"Probe workspace"}}`},
		{"apiId", "probe-api", "/apis/probe-api",
			`{"properties":{"displayName":"Probe","path":"probe","protocols":["https"],"serviceUrl":"https://backend.invalid"}}`},
		{"productId", "probe-product", "/products/probe-product",
			`{"properties":{"displayName":"Probe product"}}`},
		{"groupId", "probe-group", "/groups/probe-group",
			`{"properties":{"displayName":"Probe group"}}`},
		{"userId", "probe-user", "/users/probe-user",
			`{"properties":{"email":"probe@example.invalid","firstName":"Probe","lastName":"User"}}`},
		{"tagId", "probe-tag", "/tags/probe-tag",
			`{"properties":{"displayName":"Probe tag"}}`},
		{"backendId", "probe-backend", "/backends/probe-backend",
			`{"properties":{"url":"https://backend.invalid","protocol":"http"}}`},
		{"namedValueId", "probe-named-value", "/namedValues/probe-named-value",
			`{"properties":{"displayName":"probe","value":"probe"}}`},
		{"loggerId", "probe-logger", "/loggers/probe-logger",
			`{"properties":{"loggerType":"applicationInsights","credentials":{"instrumentationKey":"probe"}}}`},
		{"gatewayId", "probe-gateway", "/gateways/probe-gateway",
			`{"properties":{"locationData":{"name":"probe-location"},"description":"probe"}}`},
		{"authorizationProviderId", "probe-provider", "/authorizationProviders/probe-provider",
			`{"properties":{"displayName":"Probe","identityProvider":"generic","oauth2":{"redirectUrl":"https://localhost/redirect","grantTypes":{"clientCredentials":{"clientId":"id","clientSecret":"secret"}}}}}`},
		{"versionSetId", "probe-version-set", "/apiVersionSets/probe-version-set",
			`{"properties":{"displayName":"Probe","versioningScheme":"Segment"}}`},
		{"certificateId", "probe-certificate", "/certificates/probe-certificate", ""},
		{"sid", "probe-subscription", "/subscriptions/probe-subscription",
			`{"properties":{"displayName":"Probe","scope":"/products/probe-product"}}`},
	}
}

// TestOperationInventoryCoverage probes every published operation against a
// FRESH service.
//
// One emulator for the whole sweep is what the first version did, and it was
// wrong in a way that read as a result: `ApiManagementService_Delete` answered
// 204, deleted the service out from under the sweep, and every operation
// ordered after it answered 404 and was recorded as `absent`. The report looked
// precise and was an artefact of its own side effects. Probing is inherently
// destructive, so isolation is not a nicety here.
func TestOperationInventoryCoverage(t *testing.T) {
	// Gated like the other heavy witnesses. A fresh service per operation is
	// 611 emulator starts: about half a minute on a developer machine and past
	// Go's ten-minute default under CI contention, which is how it first
	// failed. It runs in its own job, with its own timeout, rather than making
	// `make verify` pay for it on every run.
	if os.Getenv("APIM_RUN_OPERATION_INVENTORY") != "1" {
		t.Skip("set APIM_RUN_OPERATION_INVENTORY=1 to probe the published operation surface")
	}
	document := loadInventory(t)

	// Paths for which Microsoft declares a PUT. This is what lets a 404 on the
	// setup call mean something: if Azure says the path accepts a create and
	// the emulator answers 404 to it with every parent present, nothing is
	// served at that path, so a sibling GET's 404 is absence too.
	creatable := map[string]bool{}
	for _, op := range document.Operations {
		if op.Method == http.MethodPut {
			creatable[op.Path] = true
		}
	}

	results := make([]result, 0, len(document.Operations))
	byGroup := map[string]sum{}
	totals := summary{Total: len(document.Operations)}
	var seedFailures []string
	var seededOnce []string

	for _, op := range document.Operations {
		emu, err := emulator.Start()
		if err != nil {
			t.Fatal(err)
		}
		client := emu.HTTPClient()
		infrastructure := map[string]string{
			"subscriptionId":    emu.SubscriptionID,
			"resourceGroupName": emu.ResourceGroup,
			"serviceName":       emu.ServiceName,
		}
		seededValues, failures := applySeeds(t, emu, client)
		if seedFailures == nil {
			seedFailures, seededOnce = failures, sortedKeys(seededValues)
		}
		verdict, status, setup := probe(t, emu, client, op, infrastructure, seededValues, creatable[op.Path])
		emu.Close()
		results = append(results, result{op.OperationID, op.Method, verdict, status, setup})
		entry := byGroup[op.Group]
		switch verdict {
		case verdictRouted:
			totals.Routed++
			entry.Routed++
		case verdictAbsent:
			totals.Absent++
			entry.Absent++
		default:
			totals.Unmeasured++
			entry.Unmeasured++
		}
		byGroup[op.Group] = entry
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].OperationID != results[j].OperationID {
			return results[i].OperationID < results[j].OperationID
		}
		return results[i].Method < results[j].Method
	})

	coverage := coverageDocument{
		Comment: []string{
			"GENERATED by e2e/inventory. Regenerate with APIM_WRITE_INVENTORY=1 go test ./e2e/inventory/...",
			"`routed` means the operation is reachable, NOT that its behaviour is correct.",
			"`absent` means a 404 that a missing resource cannot explain.",
			"`unmeasured` means a 404 this harness cannot attribute, because a parent could not be seeded.",
		},
		APIVersion: document.APIVersion,
		SpecCommit: document.SpecCommit,
		Seeded:     seededOnce,
		SeedFailed: seedFailures,
		Summary:    totals,
		ByGroup:    byGroup,
		Operations: results,
	}

	encoded, err := json.MarshalIndent(coverage, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	target := filepath.Join("..", "..", "docs", "generated", "operation-coverage-"+apiVersion+".json")
	if os.Getenv("APIM_WRITE_INVENTORY") != "" {
		if err := os.WriteFile(target, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d routed, %d absent, %d unmeasured of %d",
			target, totals.Routed, totals.Absent, totals.Unmeasured, totals.Total)
		return
	}

	committed, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("%v (regenerate with APIM_WRITE_INVENTORY=1)", err)
	}
	if string(committed) != string(encoded) {
		// The report is committed so that a change in what the emulator serves
		// shows up as a reviewable diff. Implementing an operation is supposed
		// to fail this test until the report is regenerated.
		t.Fatalf("operation coverage changed; regenerate with:\n"+
			"  APIM_WRITE_INVENTORY=1 go test ./e2e/inventory/...\n"+
			"measured: %d routed, %d absent, %d unmeasured of %d",
			totals.Routed, totals.Absent, totals.Unmeasured, totals.Total)
	}
}

// applySeeds creates probe resources and reports which parameters they satisfy.
func applySeeds(t *testing.T, emu *emulator.Emulator, client *http.Client) (map[string]string, []string) {
	t.Helper()
	seeded := map[string]string{}
	failures := []string{}
	for _, entry := range seeds() {
		if entry.body == "" {
			// No body we can honestly synthesise (a certificate needs real key
			// material). Recorded as a failure so its children stay unmeasured.
			failures = append(failures, entry.parameter+" (no synthesisable body)")
			continue
		}
		url := emu.ManagementEndpoint + emu.ServiceID() + entry.path + "?api-version=" + apiVersion
		status, _ := call(t, client, http.MethodPut, url, entry.body)
		if status >= 200 && status < 300 {
			seeded[entry.parameter] = entry.name
			continue
		}
		failures = append(failures, fmt.Sprintf("%s (PUT %s = %d)", entry.parameter, entry.path, status))
	}
	sort.Strings(failures)
	return seeded, failures
}

// probe issues one operation and decides what its response proves.
//
// For anything but a PUT it first tries to CREATE the exact resource the probe
// addresses, on the same path. That is what turns an ambiguous 404 into
// evidence: if the resource was just created and the operation still answers
// 404, no missing resource can explain it.
func probe(t *testing.T, emu *emulator.Emulator, client *http.Client, op operation,
	infrastructure, seeded map[string]string, creatable bool) (string, int, int) {
	t.Helper()

	path := op.Path
	parentsSeeded := true
	names := []string{}
	for _, match := range parameterPattern.FindAllStringSubmatch(op.Path, -1) {
		names = append(names, match[1])
	}
	for index, name := range names {
		value, ok := infrastructure[name]
		if !ok {
			value, ok = seeded[name]
		}
		if !ok {
			// The spec sometimes fixes a path segment to a constant, in which
			// case it is an address rather than a resource name.
			value, ok = op.PathEnums[name]
		}
		if !ok {
			value = "probe-absent-" + name
			if index < len(names)-1 {
				parentsSeeded = false
			}
		}
		path = strings.ReplaceAll(path, "{"+name+"}", value)
	}

	url := emu.ManagementEndpoint + path + "?api-version=" + apiVersion
	created := 0
	if op.Method != http.MethodPut {
		created, _ = call(t, client, http.MethodPut, url, leafBody(path))
	}

	body := ""
	if op.Method == http.MethodPut || op.Method == http.MethodPatch || op.Method == http.MethodPost {
		body = leafBody(path)
	}
	status, _ := call(t, client, op.Method, url, body)

	if status != http.StatusNotFound {
		return verdictRouted, status, created
	}
	if conclusiveAbsence(op.Method, names, infrastructure, seeded, parentsSeeded, created, creatable) {
		return verdictAbsent, status, created
	}
	return verdictUnmeasured, status, created
}

// conclusiveAbsence reports whether a 404 can only mean "not implemented".
//
// The rule differs by method, and the difference is the whole reason this
// harness can claim anything at all:
//   - With no resource parameters the path names a collection or a singleton.
//     An implemented collection answers even when empty, so 404 is absence.
//   - A PUT creates the resource it names, so only its PARENTS must exist.
//   - Anything else is conclusive only when the same-path PUT just created what
//     it asks for. Without that, "not implemented" and "not there" look alike.
func conclusiveAbsence(method string, names []string, infrastructure, seeded map[string]string,
	parentsSeeded bool, created int, creatable bool) bool {
	resources := 0
	for _, name := range names {
		if _, ok := infrastructure[name]; !ok {
			resources++
		}
	}
	if resources == 0 {
		return true
	}
	if method == http.MethodPut {
		return parentsSeeded
	}
	if created >= 200 && created < 300 {
		return true
	}
	// The create Azure declares for this path answered 404 while every parent
	// existed. Nothing is served here, so this operation is not either.
	return creatable && created == http.StatusNotFound && parentsSeeded
}

// leafBody is a body plausible enough for the resource a path names.
//
// Keyed on the resource FAMILY in the path (the segment before the name), so
// the same body serves a resource wherever it hangs: an API is created the same
// way at service scope and inside a workspace. Bodies are shared with the seed
// table for the same reason — two spellings of "what an API looks like" would
// drift, and the drift would show up as coverage moving for no reason.
//
// A family with no entry gets an empty properties bag. That is enough to prove
// routing, and a rejection leaves the operation honestly unmeasured rather than
// wrongly counted absent.
func leafBody(path string) string {
	segments := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(segments) < 2 {
		return emptyProperties
	}
	if body, ok := familyBodies()[strings.ToLower(segments[len(segments)-2])]; ok {
		return body
	}
	return emptyProperties
}

const emptyProperties = `{"properties":{}}`

func familyBodies() map[string]string {
	bodies := map[string]string{
		"policies":        `{"properties":{"format":"xml","value":"<policies><inbound><base /></inbound><backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>"}}`,
		"operations":      `{"properties":{"displayName":"Probe","method":"GET","urlTemplate":"/probe"}}`,
		"schemas":         `{"properties":{"contentType":"application/vnd.ms-azure-apim.xsd+xml","document":{"value":"<xsd:schema xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"/>"}}}`,
		"tagdescriptions": `{"properties":{"description":"Probe"}}`,
		"releases":        `{"properties":{"notes":"Probe"}}`,
		"resolvers":       `{"properties":{"displayName":"Probe","path":"Query/probe"}}`,
		"diagnostics":     `{"properties":{"loggerId":"probe-logger"}}`,
		"issues":          `{"properties":{"title":"Probe","description":"Probe","userId":"probe-user"}}`,
	}
	// Every family the seed table knows how to build, so a resource is created
	// the same way wherever the path puts it.
	for _, entry := range seeds() {
		if entry.body == "" {
			continue
		}
		segments := strings.Split(strings.Trim(entry.path, "/"), "/")
		if len(segments) >= 2 {
			bodies[strings.ToLower(segments[len(segments)-2])] = entry.body
		}
	}
	return bodies
}

func call(t *testing.T, client *http.Client, method, url, body string) (int, string) {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var request *http.Request
	var err error
	if reader == nil {
		request, err = http.NewRequest(method, url, nil)
	} else {
		request, err = http.NewRequest(method, url, reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload := make([]byte, 0)
	buffer := make([]byte, 4096)
	for {
		read, readErr := response.Body.Read(buffer)
		payload = append(payload, buffer[:read]...)
		if readErr != nil {
			break
		}
	}
	return response.StatusCode, string(payload)
}

func loadInventory(t *testing.T) inventoryDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", "operations-"+apiVersion+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var document inventoryDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Operations) != document.OperationCount || document.OperationCount == 0 {
		t.Fatalf("inventory is inconsistent: %d operations, count says %d",
			len(document.Operations), document.OperationCount)
	}
	return document
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
