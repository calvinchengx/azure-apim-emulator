package policy

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

// DataSource is a compiled GraphQL resolver body: the `<http-data-source>`
// element APIM puts at `/apis/{id}/resolvers/{name}/policies/policy`.
//
// It is not a Plan. A plan runs against the caller's request and produces the
// caller's response; a resolver runs per GraphQL field, produces a VALUE, and
// may run many times for one request. Modelling it as a plan would have made
// "which response is the client's" ambiguous.
type DataSource struct {
	// Request is compiled with the same grammar as <send-request>, because
	// <http-request> is the same element set. Reusing the compiler is what
	// keeps a resolver's <set-url> accepting exactly the expressions a
	// send-request <set-url> accepts, rather than a lookalike subset.
	Request Action
}

// CompileHTTPDataSource compiles a resolver policy document.
//
// Only <http-data-source> is accepted. APIM also defines
// <azure-sql-data-source> and <cosmosdb-data-source>; those are refused by name
// rather than ignored, so a caller pasting one gets told it is unimplemented
// instead of watching their resolver silently return null.
func CompileHTTPDataSource(value string) (DataSource, error) {
	var root node
	if err := xml.Unmarshal([]byte(value), &root); err != nil {
		return DataSource{}, fmt.Errorf("invalid resolver policy XML: %w", err)
	}
	if root.Name != "http-data-source" {
		return DataSource{}, fmt.Errorf("resolver policy root must be <http-data-source>, got <%s>", root.Name)
	}
	var request *node
	for index := range root.Children {
		child := root.Children[index]
		switch child.Name {
		case "http-request":
			request = &root.Children[index]
		case "http-response":
			// Response mapping (<set-body template="liquid">) shapes the
			// backend payload into the field's type. Unimplemented, and
			// refused rather than dropped: silently ignoring it would return
			// the backend's raw shape while the author believes it was
			// transformed, and the difference only shows up as wrong data.
			return DataSource{}, fmt.Errorf("%w: <http-data-source>/<http-response>", ErrUnsupported)
		default:
			return DataSource{}, fmt.Errorf("%w: <http-data-source>/<%s>", ErrUnsupported, child.Name)
		}
	}
	if request == nil {
		return DataSource{}, fmt.Errorf("<http-data-source> requires an <http-request>")
	}
	// compileSendRequest wants the element named like a send-request, and reads
	// only the children, so the rename is purely to satisfy its own error text.
	item := *request
	item.Name = "send-request"
	action, ok, err := compileSendRequest(item)
	if err != nil {
		return DataSource{}, err
	}
	if !ok || action.Kind == ActionUnsupported {
		return DataSource{}, fmt.Errorf("%w: <http-request> is missing <set-url> or <set-method>", ErrUnsupported)
	}
	return DataSource{Request: action}, nil
}

// BuildRequest renders the resolver's HTTP request for one field.
//
// Every value is evaluated against the state, which is what carries
// `context.GraphQL.Arguments` into <set-url> and <set-body>.
func (d DataSource) BuildRequest(state *State) (*http.Request, error) {
	url, err := evalValue(d.Request.SendURL, state)
	if err != nil {
		return nil, err
	}
	method, err := evalValue(d.Request.SendMethod, state)
	if err != nil {
		return nil, err
	}
	body, err := evalValue(d.Request.Body, state)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(strings.ToUpper(method), url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, header := range d.Request.Headers {
		value, err := evalValue(header.Value, state)
		if err != nil {
			return nil, err
		}
		setHeader(request.Header, Header{Name: header.Name, Value: value, Action: header.Action})
	}
	return request, nil
}
