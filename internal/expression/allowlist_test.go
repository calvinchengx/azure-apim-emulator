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
	"slices"
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
	if diff := memberDiff(document.Members, Inventory()); diff != "" {
		t.Fatalf("expression-members.json drifted from Inventory(): %s", diff)
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
	for _, member := range Inventory() {
		if member.Status != MemberPlanned {
			continue
		}
		if found[member.Type][member.Name] {
			t.Fatalf("planned %s.%s is bound; update the allowlist status", member.Type, member.Name)
		}
	}
}

func evaluationCases(t *testing.T) (*Env, map[string]string) {
	t.Helper()
	env := Bind(Context{
		Request:      httptest.NewRequest(http.MethodGet, "https://api.example/pets?x=1", nil),
		Response:     &http.Response{StatusCode: http.StatusOK},
		Variables:    map[string]string{"route": "blue"},
		LastError:    errors.New("temporary"),
		Api:          &ApiContext{Id: "pets", Name: "Pets", Path: "pets"},
		Operation:    &OperationContext{Id: "list", Name: "List", Method: http.MethodGet, UrlTemplate: "/"},
		Product:      &ProductContext{Id: "starter", Name: "Starter", Groups: []GroupContext{{Id: "devs", Name: "Developers"}}, Apis: []ApiContext{{Id: "pets", Name: "Pets"}}},
		Subscription: &SubscriptionContext{Id: "dev", Name: "Dev"},
		Backend:      &BackendContext{Id: "orders-backend", Type: "Single"},
		User:         &UserContext{Id: "ada", Email: "ada@example.test", FirstName: "Ada", LastName: "L", Note: "vip", RegistrationDate: "2026-01-01T00:00:00Z", Groups: []GroupContext{{Id: "devs", Name: "Developers"}}, Identities: []UserIdentityContext{{Id: "ada@example.test", Provider: "Basic"}}},
		Deployment: &DeploymentContext{
			ServiceName: "emulator", Region: "local", ServiceId: "/subscriptions/s/service/emulator",
			GatewayId: "managed",
			Gateway:   &GatewayContext{Id: "managed", InstanceId: "emulator", IsManaged: true},
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
		"context.Request":                "@(context.Request != null)",
		"context.Response":               "@(context.Response != null)",
		"context.Variables":              "@(context.Variables.ContainsKey('route'))",
		"context.LastError":              "@(context.LastError != null)",
		"context.Api":                    "@(context.Api != null)",
		"context.Operation":              "@(context.Operation != null)",
		"context.Product":                "@(context.Product != null)",
		"context.Subscription":           "@(context.Subscription != null)",
		"context.User":                   "@(context.User != null)",
		"context.Deployment":             "@(context.Deployment != null)",
		"Body.As":                        `@(context.Request.Body.As<string>() == "")`,
		"Body.AsFormUrlEncodedContent":   "@(context.Request.Body.AsFormUrlEncodedContent().Count)",
		"User.Email":                     "@(context.User.Email)",
		"User.FirstName":                 "@(context.User.FirstName)",
		"User.LastName":                  "@(context.User.LastName)",
		"User.Note":                      "@(context.User.Note)",
		"User.RegistrationDate":          "@(context.User.RegistrationDate)",
		"User.Groups":                    "@(context.User.Groups.Count)",
		"User.Identities":                "@(context.User.Identities.Count)",
		"Group.Id":                       "@(context.User.Groups[0].Id)",
		"Group.Name":                     "@(context.User.Groups[0].Name)",
		"UserIdentity.Id":                "@(context.User.Identities[0].Id)",
		"UserIdentity.Provider":          "@(context.User.Identities[0].Provider)",
		"Product.Groups":                 "@(context.Product.Groups.Count)",
		"Product.Apis":                   "@(context.Product.Apis.Count)",
		"context.Timestamp":              "@(context.Timestamp != null)",
		"Deployment.Certificates":        "@(context.Deployment.Certificates.Count == 1)",
		"Certificates.ContainsKey":       "@(context.Deployment.Certificates.ContainsKey('client'))",
		"Certificates.Count":             "@(context.Deployment.Certificates.Count)",
		"Request.OriginalUrl":            "@(context.Request.OriginalUrl.Path)",
		"Request.MatchedParameters":      `@(context.Request.MatchedParameters["orderId"])`,
		"Request.Certificate":            "@(context.Request.Certificate == null)",
		"Certificate.Thumbprint":         `@(context.Deployment.Certificates["client"].Thumbprint)`,
		"Certificate.Subject":            `@(context.Deployment.Certificates["client"].Subject)`,
		"Certificate.Issuer":             `@(context.Deployment.Certificates["client"].Issuer)`,
		"Certificate.SerialNumber":       `@(context.Deployment.Certificates["client"].SerialNumber)`,
		"Certificate.NotBefore":          `@(context.Deployment.Certificates["client"].NotBefore)`,
		"Certificate.NotAfter":           `@(context.Deployment.Certificates["client"].NotAfter)`,
		"Certificate.Verify":             `@(context.Deployment.Certificates["client"].Verify())`,
		"context.Elapsed":                "@(context.Elapsed != null)",
		"context.RequestId":              "@(context.RequestId != null)",
		"context.Tracing":                "@(context.Tracing == false)",
		"Api.Revision":                   "@(context.Api.Revision != null)",
		"Api.Version":                    "@(context.Api.Version != null)",
		"Api.IsCurrentRevision":          "@(context.Api.IsCurrentRevision == false)",
		"Api.ServiceUrl":                 "@(context.Api.ServiceUrl != null)",
		"Deployment.ServiceId":           "@(context.Deployment.ServiceId != null)",
		"Deployment.GatewayId":           "@(context.Deployment.GatewayId != null)",
		"Deployment.Gateway":             "@(context.Deployment.Gateway != null)",
		"Gateway.Id":                     "@(context.Deployment.Gateway.Id != null)",
		"Gateway.InstanceId":             "@(context.Deployment.Gateway.InstanceId != null)",
		"Gateway.IsManaged":              "@(context.Deployment.Gateway.IsManaged == true)",
		"Product.State":                  "@(context.Product.State != null)",
		"Product.ApprovalRequired":       "@(context.Product.ApprovalRequired == false)",
		"Product.SubscriptionRequired":   "@(context.Product.SubscriptionRequired == false)",
		"Product.SubscriptionsLimit":     "@(context.Product.SubscriptionsLimit == null)",
		"Subscription.Key":               "@(context.Subscription.Key != null)",
		"Subscription.PrimaryKey":        "@(context.Subscription.PrimaryKey != null)",
		"Subscription.SecondaryKey":      "@(context.Subscription.SecondaryKey != null)",
		"Subscription.CreatedDate":       "@(context.Subscription.CreatedDate != null)",
		"Subscription.StartDate":         "@(context.Subscription.StartDate != null)",
		"Subscription.EndDate":           "@(context.Subscription.EndDate != null)",
		"context.GraphQL":                "@(context.GraphQL != null)",
		"GraphQL.Arguments":              `@(context.GraphQL.GraphQLArguments["id"])`,
		"GraphQL.GraphQLArguments":       "@(context.GraphQL.GraphQLArguments)",
		"GraphQL.Parent":                 `@(context.GraphQL.Parent["id"])`,
		"Arguments.ContainsKey":          "@(context.GraphQL.GraphQLArguments.ContainsKey('id'))",
		"Arguments.Count":                "@(context.GraphQL.GraphQLArguments.Count)",
		"Authorization.AccessToken":      `@(((Authorization)context.Variables["auth-context"]).AccessToken)`,
		"Authorization.ClientId":         `@(((Authorization)context.Variables["auth-context"]).ClientId)`,
		"Authorization.Scopes":           `@(((Authorization)context.Variables["auth-context"]).Scopes)`,
		"Authorization.ExpiresIn":        `@(((Authorization)context.Variables["auth-context"]).ExpiresIn)`,
		"Request.Method":                 "@(context.Request.Method)",
		"Request.Url":                    "@(context.Request.Url != null)",
		"Request.Headers":                "@(context.Request.Headers.Get('X') == '')",
		"Request.IpAddress":              "@(context.Request.IpAddress != null)",
		"Request.Body":                   "@(context.Request.Body.As<string>() == '')",
		"Response.StatusCode":            "@(context.Response.StatusCode)",
		"Response.StatusReason":          "@(context.Response.StatusReason)",
		"Response.Headers":               "@(context.Response.Headers.Get('X') == '')",
		"Response.Body":                  "@(context.Response.Body.As<string>() == '')",
		"LastError.Message":              "@(context.LastError.Message)",
		"LastError.Reason":               "@(context.LastError.Reason)",
		"LastError.Scope":                "@(context.LastError.Scope)",
		"LastError.Section":              "@(context.LastError.Section)",
		"LastError.Source":               "@(context.LastError.Source)",
		"Url.Path":                       "@(context.Request.Url.Path)",
		"Url.Host":                       "@(context.Request.Url.Host)",
		"Url.Scheme":                     "@(context.Request.Url.Scheme)",
		"Url.Query":                      "@(context.Request.Url.Query)",
		"Query.GetValueOrDefault":        `@(context.Request.Url.Query.GetValueOrDefault("x", ""))`,
		"Query.ContainsKey":              `@(context.Request.Url.Query.ContainsKey("x"))`,
		"Query.Count":                    "@(context.Request.Url.Query.Count)",
		"LastError.PolicyId":             "@(context.LastError.PolicyId)",
		"Product.SubscriptionLimit":      "@(context.Product.SubscriptionLimit)",
		"Certificate.VerifyNoRevocation": `@(context.Deployment.Certificates["client"].VerifyNoRevocation())`,
		"Variables.GetValueOrDefault":    `@(context.Variables.GetValueOrDefault("v", ""))`,
		"Url.QueryString":                "@(context.Request.Url.QueryString)",
		"Url.Port":                       "@(context.Request.Url.Port)",
		"Headers.ContainsKey":            `@(context.Request.Headers.ContainsKey("X-Test"))`,
		"Headers.Count":                  "@(context.Request.Headers.Count)",
		"Headers.Get":                    "@(context.Request.Headers.Get('X'))",
		"Headers.GetValueOrDefault":      "@(context.Request.Headers.GetValueOrDefault('X', 'n'))",
		"Variables.ContainsKey":          "@(context.Variables.ContainsKey('route'))",
		"Api.Id":                         "@(context.Api.Id)",
		"Api.Name":                       "@(context.Api.Name)",
		"Api.Path":                       "@(context.Api.Path)",
		"Operation.Id":                   "@(context.Operation.Id)",
		"Operation.Name":                 "@(context.Operation.Name)",
		"Operation.Method":               "@(context.Operation.Method)",
		"Operation.UrlTemplate":          "@(context.Operation.UrlTemplate)",
		"Product.Id":                     "@(context.Product.Id)",
		"Product.Name":                   "@(context.Product.Name)",
		"Subscription.Id":                "@(context.Subscription.Id)",
		"Subscription.Name":              "@(context.Subscription.Name)",
		"User.Id":                        "@(context.User.Id)",
		"Deployment.ServiceName":         "@(context.Deployment.ServiceName)",
		"Deployment.Region":              "@(context.Deployment.Region)",
		"context.Trace":                  "@(context.Trace('hello'))",
		"Api.Protocols":                  "@(context.Api.Protocols.Count)",
		"string.AsJwt":                   `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt() != null)`,
		"string.AsBasic":                 `@('Basic YWRhOnMzY3JldA=='.AsBasic() != null)`,
		"Jwt.Id":                         `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Id)`,
		"Jwt.Algorithm":                  `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Algorithm)`,
		"Jwt.Issuer":                     `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Issuer)`,
		"Jwt.Subject":                    `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Subject)`,
		"Jwt.Type":                       `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Type)`,
		"Jwt.Audiences":                  `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Audiences.Count)`,
		"Jwt.Claims":                     `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Claims.Count)`,
		"Jwt.ExpirationTime":             `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().ExpirationTime)`,
		"Jwt.NotBefore":                  `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().NotBefore)`,
		"Jwt.IssuedAt":                   `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().IssuedAt)`,
		"Claims.GetValueOrDefault":       `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Claims.GetValueOrDefault("roles", ""))`,
		"Claims.ContainsKey":             `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Claims.ContainsKey("roles"))`,
		"Claims.Count":                   `@("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoic3ViamVjdCIsImF1ZCI6WyJhIiwiYiJdLCJleHAiOjIwMDAwMDAwMDAsIm5iZiI6MTAwMDAwMDAwMCwiaWF0IjoxMDAwMDAwMDAwLCJyb2xlcyI6WyJhZG1pbiJdfQ.sig".AsJwt().Claims.Count)`,
		"BasicAuthCredentials.Username":  `@('Basic YWRhOnMzY3JldA=='.AsBasic().Username)`,
		"BasicAuthCredentials.Password":  `@('Basic YWRhOnMzY3JldA=='.AsBasic().Password)`,
		"context.Backend":                "@(context.Backend)",
		"Backend.Id":                     "@(context.Backend.Id)",
		"Backend.Type":                   "@(context.Backend.Type)",
		"value.ToString":                 "@(1.ToString())",
		"string.Length":                  "@('ab'.Length)",
	}
	return env, cases
}

func TestAllowlistBoundMembersEvaluate(t *testing.T) {
	env, cases := evaluationCases(t)
	for _, member := range Allowlist() {
		// Framework members are Microsoft-backed claims that sit on the binder,
		// so they must evaluate for the same reason bound members must. Only
		// extensions are exempt: they are ours, and named as such.
		if member.Status != MemberBound && member.Status != MemberFramework {
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
	for _, member := range Inventory() {
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
		// Framework members sit on the binder too: the .NET type is available in
		// a tenant, so the binder answers them. Only `planned` is absent.
		if member.Status == MemberPlanned {
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
		"contextHost":          {"context"},
		"requestHost":          {"Request"},
		"responseHost":         {"Response"},
		"lastErrorHost":        {"LastError"},
		"urlHost":              {"Url"},
		"headerHost":           {"Headers"},
		"mapHost":              {"Variables"},
		"bodyHost":             {"Body"},
		"apiHost":              {"Api"},
		"operationHost":        {"Operation"},
		"namedHost":            {},
		"userHost":             {"User"},
		"groupHost":            {"Group"},
		"userIdentityHost":     {"UserIdentity"},
		"listHost":             {},
		"formHost":             {},
		"productHost":          {"Product"},
		"subscriptionHost":     {"Subscription"},
		"deploymentHost":       {"Deployment"},
		"gatewayHost":          {"Gateway"},
		"certificateHost":      {"Certificate"},
		"certificateMapHost":   {"Certificates"},
		"graphQLHost":          {"GraphQL"},
		"jsonMapHost":          {"Arguments"},
		"queryHost":            {"Query"},
		"backendHost":          {"Backend"},
		"jwtHost":              {"Jwt"},
		"claimsHost":           {"Claims"},
		"basicCredentialsHost": {"BasicAuthCredentials"},
		"authorizationHost":    {"Authorization"},
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
	for _, name := range []string{"context.go", "graphql.go", "collections.go", "jwt.go"} {
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
// The ledger is generated rather than hand-edited. Running the suite with
// APIM_UPDATE_LEDGER=1 rewrites it from Inventory(); CI runs without it, so a
// stale ledger fails the drift test above instead of being silently rewritten.
func TestUpdateLedger(t *testing.T) {
	if os.Getenv("APIM_UPDATE_LEDGER") != "1" {
		t.Skip("set APIM_UPDATE_LEDGER=1 to regenerate docs/generated/expression-members.json")
	}
	path := filepath.Join("..", "..", "docs", "generated", "expression-members.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Source  string   `json:"source"`
		Status  string   `json:"status"`
		Members []Member `json:"members"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document.Members = Inventory()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("rewrote %s with %d members", path, len(document.Members))
}

func TestEveryDocumentedMemberIsClassified(t *testing.T) {
	listed := map[string]map[string]bool{}
	for _, member := range Inventory() {
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
		t.Fatalf("%d documented member(s) missing from the inventory: %s", len(missing), strings.Join(missing, ", "))
	}
	// The inventory computes planned rows, so the property worth guarding is
	// that it computes them from the DOCUMENTED surface rather than from
	// nothing: a planned row for a member nobody documents would be invented.
	documented := documentedIndex()
	for _, member := range Inventory() {
		if member.Status == MemberPlanned && !documented[member.Type][member.Name] {
			t.Fatalf("%s.%s is planned but nobody documents it", member.Type, member.Name)
		}
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
		// A framework member reads a .NET type Microsoft lists as available.
		// The type must actually appear on that list, or the entry is an
		// extension wearing a stronger label.
		if member.Status == MemberFramework {
			dotted, ok := frameworkTypeOf(member.Type)
			if !ok {
				t.Fatalf("%s is framework-classified without naming a .NET type", member.Type)
			}
			if !slices.Contains(FrameworkTypes(), dotted) {
				t.Fatalf("%s claims .NET type %s, which Microsoft's reference does not list", member.Type, dotted)
			}
			continue
		}
		t.Fatalf("allowlist has %s.%s, which Azure does not document and which is not a declared helper",
			member.Type, member.Name)
	}
}

// A planned member must not resolve. A binder that answered one anyway would
// make the ledger's own count wrong in the flattering direction.
// The canary this replaces asserted there is always at least one PLANNED
// member, which stopped being true the moment the surface was completed. What
// it was really guarding is the inventory silently emptying, so that is what it
// checks now: a documented surface that shrank to nothing would pass every
// other test in this file.
func TestDocumentedSurfaceIsNotEmpty(t *testing.T) {
	if len(Documented()) < 125 {
		t.Fatalf("the documented surface has %d members; it had 131, so the inventory stopped measuring", len(Documented()))
	}
	// The surface is derived from vendored sources, so an empty or unreadable
	// vendor directory must not read as "Microsoft documents nothing".
	if len(FrameworkTypes()) < 100 {
		t.Fatalf("the allowed .NET type list has %d entries; it had 130", len(FrameworkTypes()))
	}
	// And every planned member, if any remain, must genuinely not resolve --
	// a planned member that answers would make the ledger's own count wrong in
	// the flattering direction.
	env := Bind(Context{})
	for _, member := range Allowlist() {
		if member.Status != MemberPlanned {
			continue
		}
		if _, err := EvalEnv("@(context."+member.Type+"."+member.Name+")", env); err == nil {
			t.Fatalf("planned %s.%s resolved", member.Type, member.Name)
		}
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
