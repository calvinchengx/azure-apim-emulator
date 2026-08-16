package policy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	expr "github.com/calvinchengx/azure-apim-emulator/internal/expression"
)

func TestCompileHTTPDataSourceAcceptsAResolverBody(t *testing.T) {
	source, err := CompileHTTPDataSource(`<http-data-source>
	  <http-request>
	    <set-method>GET</set-method>
	    <set-url>https://data.test/orders</set-url>
	    <set-header name="X-Trace" exists-action="override"><value>on</value></set-header>
	  </http-request>
	</http-data-source>`)
	if err != nil {
		t.Fatal(err)
	}
	if source.Request.SendMethod != "GET" || source.Request.SendURL != "https://data.test/orders" {
		t.Fatalf("compiled request = %+v", source.Request)
	}
	if len(source.Request.Headers) != 1 || source.Request.Headers[0].Name != "X-Trace" {
		t.Fatalf("headers = %+v", source.Request.Headers)
	}
}

func TestCompileHTTPDataSourceRefusesWhatItCannotRun(t *testing.T) {
	tests := map[string]string{
		"not XML":            "<http-data-source",
		"wrong root":         "<policies><inbound/></policies>",
		"no http-request":    "<http-data-source></http-data-source>",
		"no url":             "<http-data-source><http-request><set-method>GET</set-method></http-request></http-data-source>",
		"unknown child":      "<http-data-source><nonsense/></http-data-source>",
		"bad expression":     `<http-data-source><http-request><set-method>GET</set-method><set-url>@(</set-url></http-request></http-data-source>`,
		"unknown grandchild": "<http-data-source><http-request><set-method>GET</set-method><set-url>https://x</set-url><nonsense/></http-request></http-data-source>",
	}
	for name, document := range tests {
		if _, err := CompileHTTPDataSource(document); err == nil {
			t.Errorf("CompileHTTPDataSource accepted %s", name)
		}
	}
}

// http-response shapes the payload into the field's type. It is refused rather
// than dropped, because ignoring it returns the backend's raw shape while the
// author believes it was transformed.
func TestCompileHTTPDataSourceRefusesResponseMappingRatherThanIgnoringIt(t *testing.T) {
	_, err := CompileHTTPDataSource(`<http-data-source>
	  <http-request><set-method>GET</set-method><set-url>https://x</set-url></http-request>
	  <http-response><set-body template="liquid">{}</set-body></http-response>
	</http-data-source>`)
	if err == nil {
		t.Fatal("an unimplemented http-response must be refused, not silently dropped")
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported so the caller can tell it apart from a malformed document", err)
	}
}

// The argument reaches the URL through context.GraphQL.Arguments, which is the
// documented Azure member and the reason resolvers needed it.
func TestBuildRequestEvaluatesGraphQLArguments(t *testing.T) {
	source, err := CompileHTTPDataSource(`<http-data-source><http-request>
	    <set-method>POST</set-method>
	    <set-url>@("https://data.test/orders/" + context.GraphQL.Arguments["ref"])</set-url>
	    <set-header name="X-Parent" exists-action="override"><value>@(context.GraphQL.Parent["customerId"])</value></set-header>
	    <set-body>@(context.GraphQL.Arguments["ref"])</set-body>
	  </http-request></http-data-source>`)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{GraphQL: &expr.GraphQLContext{
		Arguments: map[string]any{"ref": "A-1"},
		Parent:    map[string]any{"customerId": "c9"},
	}}
	request, err := source.BuildRequest(state)
	if err != nil {
		t.Fatal(err)
	}
	if request.URL.String() != "https://data.test/orders/A-1" {
		t.Fatalf("URL = %s", request.URL)
	}
	if request.Method != http.MethodPost {
		t.Fatalf("method = %s", request.Method)
	}
	if got := request.Header.Get("X-Parent"); got != "c9" {
		t.Fatalf("parent header = %q", got)
	}
	body, _ := io.ReadAll(request.Body)
	if string(body) != "A-1" {
		t.Fatalf("body = %q", body)
	}
}

func TestBuildRequestReportsEvaluationFailures(t *testing.T) {
	// No GraphQL binding: context.GraphQL is null, so member access on it fails
	// rather than quietly yielding an empty argument set.
	source, err := CompileHTTPDataSource(`<http-data-source><http-request>
	    <set-method>GET</set-method>
	    <set-url>@("https://x/" + context.GraphQL.Arguments["ref"])</set-url>
	  </http-request></http-data-source>`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.BuildRequest(&State{}); err == nil {
		t.Fatal("evaluating context.GraphQL with no binding must fail")
	}

	for name, document := range map[string]string{
		"method": `<http-data-source><http-request><set-method>@(context.GraphQL.Arguments["m"])</set-method><set-url>https://x</set-url></http-request></http-data-source>`,
		"body":   `<http-data-source><http-request><set-method>GET</set-method><set-url>https://x</set-url><set-body>@(context.GraphQL.Arguments["b"])</set-body></http-request></http-data-source>`,
		"header": `<http-data-source><http-request><set-method>GET</set-method><set-url>https://x</set-url><set-header name="H" exists-action="override"><value>@(context.GraphQL.Arguments["h"])</value></set-header></http-request></http-data-source>`,
	} {
		compiled, compileErr := CompileHTTPDataSource(document)
		if compileErr != nil {
			t.Fatalf("%s: %v", name, compileErr)
		}
		if _, err := compiled.BuildRequest(&State{}); err == nil {
			t.Errorf("%s: an unevaluatable value must be reported", name)
		}
	}

	// A URL the http package cannot parse fails at construction.
	invalid, err := CompileHTTPDataSource(`<http-data-source><http-request><set-method>GET</set-method><set-url>://nope</set-url></http-request></http-data-source>`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.BuildRequest(&State{}); err == nil {
		t.Fatal("an unparseable URL must be reported")
	}
}

func TestBuildRequestWithNoBody(t *testing.T) {
	source, err := CompileHTTPDataSource(`<http-data-source><http-request><set-method>get</set-method><set-url>https://data.test/x</set-url></http-request></http-data-source>`)
	if err != nil {
		t.Fatal(err)
	}
	request, err := source.BuildRequest(&State{})
	if err != nil {
		t.Fatal(err)
	}
	// The method is upper-cased, so a lower-case <set-method> still produces a
	// conventional request rather than a method servers reject.
	if request.Method != http.MethodGet {
		t.Fatalf("method = %q", request.Method)
	}
	body, _ := io.ReadAll(request.Body)
	if strings.TrimSpace(string(body)) != "" {
		t.Fatalf("body = %q", body)
	}
}
