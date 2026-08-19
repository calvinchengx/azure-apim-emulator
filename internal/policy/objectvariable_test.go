package policy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// set-variable keeps an object rather than only its rendering, which is what
// `((Jwt)context.Variables["token"]).Claims` reads. Driven through a compiled
// policy rather than a hand-built state, because the failure this guards is
// set-variable flattening the value on the way in.
func TestSetVariableKeepsObjects(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJqdGkiOiJpZC0xIiwiaXNzIjoiaXNzdWVyIiwic3ViIjoiYWRhIiwicm9sZXMiOlsiYWRtaW4iXX0.sig"
	plan, err := Compile(`<policies><inbound>`+
		`<set-variable name="jwt"><value>@("`+token+`".AsJwt())</value></set-variable>`+
		`<set-header name="X-Subject" exists-action="override"><value>@(((Jwt)context.Variables["jwt"]).Subject)</value></set-header>`+
		`<set-header name="X-Role" exists-action="override"><value>@(((Jwt)context.Variables["jwt"]).Claims["roles"][0])</value></set-header>`+
		`</inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := state.Request.Header.Get("X-Subject"); got != "ada" {
		t.Fatalf("subject through a variable = %q", got)
	}
	if got := state.Request.Header.Get("X-Role"); got != "admin" {
		t.Fatalf("claim through a variable = %q", got)
	}
}

// The text map still holds the rendering, so every consumer that reads
// variables as text keeps working.
func TestSetVariableStillRendersToText(t *testing.T) {
	plan, err := Compile(`<policies><inbound>`+
		`<set-variable name="payload"><value>@(new JObject(new JProperty("a", 1)))</value></set-variable>`+
		`<set-body>@(context.Variables["payload"].ToString())</set-body>`+
		`</inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if state.Variables["payload"] != `{"a":1}` {
		t.Fatalf("text rendering = %q", state.Variables["payload"])
	}
	// With a request and no response, set-body writes the request's body.
	replayed, err := state.Request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(replayed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"a":1`) {
		t.Fatalf("body = %q", string(body))
	}
}

// Overwriting an object variable with text clears the object, so a later member
// read fails rather than resolving against a value that was replaced.
func TestSetVariableOverwriteClearsTheObject(t *testing.T) {
	plan, err := Compile(`<policies><inbound>`+
		`<set-variable name="v"><value>@(new JObject(new JProperty("a", 1)))</value></set-variable>`+
		`<set-variable name="v"><value>plain</value></set-variable>`+
		`</inbound></policies>`, true)
	if err != nil {
		t.Fatal(err)
	}
	state := &State{Request: httptest.NewRequest(http.MethodGet, "/", nil)}
	if err := Execute(plan.Inbound, state); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if state.Variables["v"] != "plain" {
		t.Fatalf("overwritten text = %q", state.Variables["v"])
	}
	if _, still := state.VariableObjects["v"]; still {
		t.Fatal("the object survived being overwritten by text")
	}
}
