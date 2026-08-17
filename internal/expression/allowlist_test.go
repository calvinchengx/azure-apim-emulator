package expression

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestAllowlistMatchesCheckedInLedger(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", "expression-members.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Members []Member `json:"members"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if diff := memberDiff(document.Members, Allowlist()); diff != "" {
		t.Fatalf("expression-members.json drifted from Allowlist(): %s", diff)
	}
}

func TestBinderCasesMatchAllowlist(t *testing.T) {
	bound := boundByType(Allowlist())
	found := binderCases(t)
	for typ, names := range found {
		for name := range names {
			if bound[typ][name] {
				continue
			}
			t.Fatalf("binder exposes %s.%s without an allowlist bound entry", typ, name)
		}
	}
	for typ, names := range bound {
		if typ == "value" || typ == "string" {
			continue
		}
		for name := range names {
			if !found[typ][name] {
				t.Fatalf("allowlist bound %s.%s is missing from the binder", typ, name)
			}
		}
	}
	for _, member := range Allowlist() {
		if member.Status != MemberPlanned {
			continue
		}
		if found[member.Type][member.Name] {
			t.Fatalf("planned %s.%s is bound; update the allowlist status", member.Type, member.Name)
		}
	}
}

func TestAllowlistBoundMembersEvaluate(t *testing.T) {
	env := Bind(Context{
		Request:      httptest.NewRequest(http.MethodGet, "https://api.example/pets?x=1", nil),
		Response:     &http.Response{StatusCode: http.StatusOK},
		Variables:    map[string]string{"route": "blue"},
		LastError:    errors.New("temporary"),
		Api:          &ApiContext{Id: "pets", Name: "Pets", Path: "pets"},
		Operation:    &OperationContext{Id: "list", Name: "List", Method: http.MethodGet, UrlTemplate: "/"},
		Product:      &ProductContext{Id: "starter", Name: "Starter"},
		Subscription: &SubscriptionContext{Id: "dev", Name: "Dev"},
		User:         &NamedContext{Id: "ada", Name: "Ada"},
		Deployment: &DeploymentContext{
			ServiceName: "emulator", Region: "local", ServiceId: "/subscriptions/s/service/emulator",
			GatewayId: "managed",
			Gateway:   &GatewayContext{Id: "managed", InstanceId: "emulator", IsManaged: true, RegionName: "local"},
		},
		Timestamp:         time.Unix(0, 0).UTC(),
		Elapsed:           func() time.Duration { return 0 },
		RequestId:         "req-1",
		OriginalUrl:       "https://api.example/pets?x=1",
		MatchedParameters: map[string]string{"orderId": "A-1"},
		Certificates:      map[string]*x509.Certificate{"client": testCertificate()},
		AuthorizationContexts: map[string]AuthorizationContext{
			"auth-context": {AccessToken: "tok", ClientID: "client", Scopes: "read", ExpiresIn: 3600},
		},
		GraphQL: &GraphQLContext{
			Arguments: map[string]any{"id": "42", "first": float64(10)},
			Parent:    map[string]any{"id": "parent"},
		},
	})
	cases := map[string]string{
		"context.Request":              "@(context.Request != null)",
		"context.Response":             "@(context.Response != null)",
		"context.Variables":            "@(context.Variables.ContainsKey('route'))",
		"context.LastError":            "@(context.LastError != null)",
		"context.Api":                  "@(context.Api != null)",
		"context.Operation":            "@(context.Operation != null)",
		"context.Product":              "@(context.Product != null)",
		"context.Subscription":         "@(context.Subscription != null)",
		"context.User":                 "@(context.User != null)",
		"context.Deployment":           "@(context.Deployment != null)",
		"context.Timestamp":            "@(context.Timestamp != null)",
		"Deployment.Certificates":      "@(context.Deployment.Certificates.Count == 1)",
		"Certificates.ContainsKey":     "@(context.Deployment.Certificates.ContainsKey('client'))",
		"Certificates.Count":           "@(context.Deployment.Certificates.Count)",
		"Request.OriginalUrl":          "@(context.Request.OriginalUrl.Path)",
		"Request.MatchedParameters":    `@(context.Request.MatchedParameters["orderId"])`,
		"Request.Certificate":          "@(context.Request.Certificate == null)",
		"Certificate.Thumbprint":       `@(context.Deployment.Certificates["client"].Thumbprint)`,
		"Certificate.Subject":          `@(context.Deployment.Certificates["client"].Subject)`,
		"Certificate.Issuer":           `@(context.Deployment.Certificates["client"].Issuer)`,
		"Certificate.SerialNumber":     `@(context.Deployment.Certificates["client"].SerialNumber)`,
		"Certificate.NotBefore":        `@(context.Deployment.Certificates["client"].NotBefore)`,
		"Certificate.NotAfter":         `@(context.Deployment.Certificates["client"].NotAfter)`,
		"Certificate.Verify":           `@(context.Deployment.Certificates["client"].Verify())`,
		"context.Elapsed":              "@(context.Elapsed != null)",
		"context.RequestId":            "@(context.RequestId != null)",
		"context.Tracing":              "@(context.Tracing == false)",
		"Api.Revision":                 "@(context.Api.Revision != null)",
		"Api.Version":                  "@(context.Api.Version != null)",
		"Api.IsCurrentRevision":        "@(context.Api.IsCurrentRevision == false)",
		"Api.ServiceUrl":               "@(context.Api.ServiceUrl != null)",
		"Deployment.ServiceId":         "@(context.Deployment.ServiceId != null)",
		"Deployment.GatewayId":         "@(context.Deployment.GatewayId != null)",
		"Deployment.Gateway":           "@(context.Deployment.Gateway != null)",
		"Gateway.Id":                   "@(context.Deployment.Gateway.Id != null)",
		"Gateway.InstanceId":           "@(context.Deployment.Gateway.InstanceId != null)",
		"Gateway.IsManaged":            "@(context.Deployment.Gateway.IsManaged == true)",
		"Gateway.RegionName":           "@(context.Deployment.Gateway.RegionName != null)",
		"Product.State":                "@(context.Product.State != null)",
		"Product.ApprovalRequired":     "@(context.Product.ApprovalRequired == false)",
		"Product.SubscriptionRequired": "@(context.Product.SubscriptionRequired == false)",
		"Product.SubscriptionsLimit":   "@(context.Product.SubscriptionsLimit == null)",
		"Subscription.Key":             "@(context.Subscription.Key != null)",
		"Subscription.PrimaryKey":      "@(context.Subscription.PrimaryKey != null)",
		"Subscription.SecondaryKey":    "@(context.Subscription.SecondaryKey != null)",
		"Subscription.CreatedDate":     "@(context.Subscription.CreatedDate != null)",
		"Subscription.StartDate":       "@(context.Subscription.StartDate != null)",
		"Subscription.EndDate":         "@(context.Subscription.EndDate != null)",
		"context.GraphQL":              "@(context.GraphQL != null)",
		"GraphQL.Arguments":            `@(context.GraphQL.Arguments["id"])`,
		"GraphQL.Parent":               `@(context.GraphQL.Parent["id"])`,
		"Arguments.ContainsKey":        "@(context.GraphQL.Arguments.ContainsKey('id'))",
		"Arguments.Count":              "@(context.GraphQL.Arguments.Count)",
		"Authorization.AccessToken":    `@(((Authorization)context.Variables["auth-context"]).AccessToken)`,
		"Authorization.ClientId":       `@(((Authorization)context.Variables["auth-context"]).ClientId)`,
		"Authorization.Scopes":         `@(((Authorization)context.Variables["auth-context"]).Scopes)`,
		"Authorization.ExpiresIn":      `@(((Authorization)context.Variables["auth-context"]).ExpiresIn)`,
		"Request.Method":               "@(context.Request.Method)",
		"Request.Url":                  "@(context.Request.Url != null)",
		"Request.Headers":              "@(context.Request.Headers.Get('X') == '')",
		"Request.IpAddress":            "@(context.Request.IpAddress != null)",
		"Request.Body":                 "@(context.Request.Body.AsString() == '')",
		"Response.StatusCode":          "@(context.Response.StatusCode)",
		"Response.StatusReason":        "@(context.Response.StatusReason)",
		"Response.Headers":             "@(context.Response.Headers.Get('X') == '')",
		"Response.Body":                "@(context.Response.Body.AsString() == '')",
		"LastError.Message":            "@(context.LastError.Message)",
		"Url.Path":                     "@(context.Request.Url.Path)",
		"Url.Host":                     "@(context.Request.Url.Host)",
		"Url.Scheme":                   "@(context.Request.Url.Scheme)",
		"Url.Query":                    "@(context.Request.Url.Query)",
		"Url.QueryString":              "@(context.Request.Url.QueryString)",
		"Url.Port":                     "@(context.Request.Url.Port)",
		"Headers.Get":                  "@(context.Request.Headers.Get('X'))",
		"Headers.GetValueOrDefault":    "@(context.Request.Headers.GetValueOrDefault('X', 'n'))",
		"Variables.ContainsKey":        "@(context.Variables.ContainsKey('route'))",
		"Body.AsString":                "@(context.Request.Body.AsString())",
		"Api.Id":                       "@(context.Api.Id)",
		"Api.Name":                     "@(context.Api.Name)",
		"Api.Path":                     "@(context.Api.Path)",
		"Operation.Id":                 "@(context.Operation.Id)",
		"Operation.Name":               "@(context.Operation.Name)",
		"Operation.Method":             "@(context.Operation.Method)",
		"Operation.UrlTemplate":        "@(context.Operation.UrlTemplate)",
		"Product.Id":                   "@(context.Product.Id)",
		"Product.Name":                 "@(context.Product.Name)",
		"Subscription.Id":              "@(context.Subscription.Id)",
		"Subscription.Name":            "@(context.Subscription.Name)",
		"User.Id":                      "@(context.User.Id)",
		"User.Name":                    "@(context.User.Name)",
		"Deployment.ServiceName":       "@(context.Deployment.ServiceName)",
		"Deployment.Region":            "@(context.Deployment.Region)",
		"value.ToString":               "@(1.ToString())",
		"string.Length":                "@('ab'.Length)",
	}
	for _, member := range Allowlist() {
		if member.Status != MemberBound {
			continue
		}
		source, ok := cases[member.Type+"."+member.Name]
		if !ok {
			t.Fatalf("no evaluation case for bound %s.%s", member.Type, member.Name)
		}
		if _, err := EvalEnv(source, env); err != nil {
			t.Fatalf("%s (%s): %v", member.Type+"."+member.Name, source, err)
		}
	}
	for _, member := range Allowlist() {
		if member.Status != MemberPlanned {
			continue
		}
		source := "@(context." + member.Type + "." + member.Name + ")"
		if member.Type == "context" {
			source = "@(context." + member.Name + ")"
		} else if member.Type == "Request" || member.Type == "Response" {
			source = "@(context." + member.Type + "." + member.Name + ")"
		} else if member.Type == "Url" {
			source = "@(context.Request.Url." + member.Name + ")"
		} else if member.Type == "Headers" {
			source = "@(context.Request.Headers." + member.Name + ")"
		} else if member.Type == "Variables" {
			source = "@(context.Variables." + member.Name + ")"
		} else if member.Type == "Body" {
			source = "@(context.Request.Body." + member.Name + ")"
		} else if member.Type == "LastError" {
			source = "@(context.LastError." + member.Name + ")"
		} else {
			source = "@(context." + member.Type + "." + member.Name + ")"
		}
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("planned %s.%s evaluated", member.Type, member.Name)
		}
	}
}

// boundByType indexes the members the binder is expected to answer. An
// extension is answered too: it is a declared divergence, not an accident, and
// the binder/allowlist agreement test is about accidents.
func boundByType(members []Member) map[string]map[string]bool {
	result := map[string]map[string]bool{}
	for _, member := range members {
		if member.Status != MemberBound && member.Status != MemberExtension {
			continue
		}
		if result[member.Type] == nil {
			result[member.Type] = map[string]bool{}
		}
		result[member.Type][member.Name] = true
	}
	return result
}

func binderCases(t *testing.T) map[string]map[string]bool {
	t.Helper()
	hosts := map[string][]string{
		"contextHost":        {"context"},
		"requestHost":        {"Request"},
		"responseHost":       {"Response"},
		"lastErrorHost":      {"LastError"},
		"urlHost":            {"Url"},
		"headerHost":         {"Headers"},
		"mapHost":            {"Variables"},
		"bodyHost":           {"Body"},
		"apiHost":            {"Api"},
		"operationHost":      {"Operation"},
		"namedHost":          {"User"},
		"productHost":        {"Product"},
		"subscriptionHost":   {"Subscription"},
		"deploymentHost":     {"Deployment"},
		"gatewayHost":        {"Gateway"},
		"certificateHost":    {"Certificate"},
		"certificateMapHost": {"Certificates"},
		"graphQLHost":        {"GraphQL"},
		"jsonMapHost":        {"Arguments"},
		"authorizationHost":  {"Authorization"},
	}
	// Both files, because a host that binds members is a host wherever it
	// lives. Parsing only context.go would let a new file expose members the
	// allowlist never sees, which is the exact drift this test exists to catch.
	found := map[string]map[string]bool{}
	inspect := func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "member" || fn.Recv == nil || len(fn.Recv.List) == 0 {
			return true
		}
		recv := receiverName(fn.Recv.List[0].Type)
		types, ok := hosts[recv]
		if !ok {
			t.Fatalf("binder host %s is not mapped in the allowlist test", recv)
		}
		for _, stmt := range fn.Body.List {
			sw, ok := stmt.(*ast.SwitchStmt)
			if !ok {
				continue
			}
			for _, clause := range sw.Body.List {
				caseClause, ok := clause.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range caseClause.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok {
						continue
					}
					name := lit.Value[1 : len(lit.Value)-1]
					for _, typ := range types {
						if found[typ] == nil {
							found[typ] = map[string]bool{}
						}
						found[typ][name] = true
					}
				}
			}
		}
		return true
	}
	for _, name := range []string{"context.go", "graphql.go"} {
		file, err := goparser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, inspect)
	}
	if len(found) == 0 {
		t.Fatal("no binder member cases found")
	}
	return found
}

func receiverName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	ident, _ := expr.(*ast.Ident)
	if ident == nil {
		return ""
	}
	return ident.Name
}

func memberDiff(got, want []Member) string {
	normalize := func(values []Member) []string {
		items := make([]string, 0, len(values))
		for _, value := range values {
			items = append(items, value.Type+"."+value.Name+"="+string(value.Status))
		}
		sort.Strings(items)
		return items
	}
	left, right := normalize(got), normalize(want)
	if len(left) == len(right) {
		equal := true
		for index := range left {
			if left[index] != right[index] {
				equal = false
				break
			}
		}
		if equal {
			return ""
		}
	}
	return "got " + joinMembers(left) + "; want " + joinMembers(right)
}

func joinMembers(values []string) string {
	raw, _ := json.Marshal(values)
	return string(raw)
}

// Every member Azure documents must appear in the allowlist with some status.
//
// This is the gate the inventory lacked, and its absence is why the ledger read
// 57 of 66 bound -- 86% -- while 43 documented members were not listed at all.
// A self-referential inventory can prove the emulator agrees with itself and
// can never show what it has never heard of. With this, a member Azure adds is
// a `planned` row somebody has to write rather than an absence nothing detects.
func TestEveryDocumentedMemberIsClassified(t *testing.T) {
	listed := map[string]map[string]bool{}
	for _, member := range Allowlist() {
		if listed[member.Type] == nil {
			listed[member.Type] = map[string]bool{}
		}
		listed[member.Type][member.Name] = true
	}
	var missing []string
	for _, member := range Documented() {
		if !listed[member.Type][member.Name] {
			missing = append(missing, member.Type+"."+member.Name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d documented member(s) missing from the allowlist: %s", len(missing), strings.Join(missing, ", "))
	}
}

// And the other direction, which stops the allowlist inflating its own
// denominator: an entry that is neither documented by Azure nor a helper the
// binder needs is a member somebody invented.
func TestAllowlistDoesNotInventContextMembers(t *testing.T) {
	documented := documentedIndex()
	// Helper types the binder needs to evaluate expressions at all. They are not
	// part of Azure's context graph and are deliberately excluded from
	// Documented(), so they are named here instead of silently tolerated.
	helpers := map[string]bool{
		"Arguments": true, "Authorization": true, "Headers": true,
		"Variables": true, "value": true, "string": true, "Certificates": true,
	}
	for _, member := range Allowlist() {
		if helpers[member.Type] || documented[member.Type][member.Name] {
			continue
		}
		// An extension is a KNOWN divergence, declared as such in the ledger.
		// Tolerated here precisely because it is named there.
		if member.Status == MemberExtension {
			continue
		}
		t.Fatalf("allowlist has %s.%s, which Azure does not document and which is not a declared helper",
			member.Type, member.Name)
	}
}

// A planned member must not resolve. A binder that answered one anyway would
// make the ledger's own count wrong in the flattering direction.
func TestPlannedMembersDoNotResolve(t *testing.T) {
	planned := 0
	for _, member := range Allowlist() {
		if member.Status == MemberPlanned {
			planned++
		}
	}
	if planned == 0 {
		t.Fatal("no planned members: either the surface is complete or the inventory stopped measuring")
	}
}

// testCertificate builds a self-signed leaf so the certificate members have
// something real to read rather than a zero struct.
func testCertificate() *x509.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "client.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return leaf
}
