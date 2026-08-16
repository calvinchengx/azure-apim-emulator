package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/graphql"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// GraphQLSchemaContentType is the content type Azure gives a GraphQL schema
// resource under an API. The schema is stored through the same
// `/apis/{id}/schemas/{name}` resource every other schema uses; only this
// discriminator says which one is GraphQL.
const GraphQLSchemaContentType = "application/vnd.ms-azure-apim.graphql.schema"

// graphQLAPIType is the value of `properties.apiType` that marks a GraphQL API.
const graphQLAPIType = "graphql"

// graphQLSchemaFor compiles the GraphQL schema of a GraphQL API, and returns
// nil for anything else.
//
// Both conditions are required, and the pairing is the point: a schema attached
// to a REST API is a document the gateway must not act on, and an apiType with
// no schema behind it describes nothing the gateway could serve. Reading either
// signal alone would turn a misconfiguration into GraphQL traffic.
//
// A GraphQL API with no schema YET is not an error. ARM has no way to create
// both at once: `/apis/{id}` and `/apis/{id}/schemas/{name}` are separate
// resources, so every import necessarily passes through that state. Rejecting
// it would make the documented create-then-import order impossible. Such an API
// simply is not GraphQL-routable until its schema arrives. A schema that is
// present but unparseable IS an error, because that one is a real defect and
// nothing later will fix it.
func graphQLSchemaFor(st *store.Store, api model.API) (*graphql.Schema, error) {
	if !isGraphQLAPI(api) {
		return nil, nil
	}
	schemas, err := st.ListAPISchemas(api.ID())
	if err != nil {
		return nil, err
	}
	for _, schema := range schemas {
		if !strings.EqualFold(schema.ContentType, GraphQLSchemaContentType) {
			continue
		}
		sdl, _ := schema.Document["value"].(string)
		compiled, err := graphql.Parse(sdl)
		if err != nil {
			return nil, fmt.Errorf("API %s: %w", api.ID(), err)
		}
		return compiled, nil
	}
	return nil, nil
}

func isGraphQLAPI(api model.API) bool {
	properties, _ := api.Document["properties"].(map[string]any)
	apiType, _ := properties["apiType"].(string)
	return strings.EqualFold(apiType, graphQLAPIType)
}

// serveGraphQL answers a request against a GraphQL API.
//
// It runs after the inbound and backend policy phases, so subscription keys,
// rate limits, header rewriting and backend selection all behave exactly as
// they do for a REST API. What it replaces is only the forwarding step.
func (r *Runtime) serveGraphQL(w http.ResponseWriter, req *http.Request, service *Service, route *Route, state *policy.State, plan policy.Plan) {
	request, body, err := graphql.DecodeRequest(req)
	if err != nil {
		writeGraphQLError(w, http.StatusBadRequest, graphql.ErrorMessage("%s", err.Error()))
		return
	}
	operation, errs := route.GraphQL.Compile(request)
	if len(errs) > 0 {
		// A query that does not match the schema is refused HERE rather than
		// forwarded. That is the whole value of putting a schema on the
		// gateway: the backend never sees a request it would have to reject,
		// and the caller gets the same error whichever backend is behind it.
		writeGraphQLError(w, http.StatusBadRequest, graphql.ErrorBody(errs))
		return
	}
	state.Trace("graphql", strings.Join(operation.RootFields(), ","))
	if operation.IsIntrospection() {
		// Answered from the schema, never forwarded. Production GraphQL
		// backends routinely disable introspection, and APIM still answers it
		// from the schema it holds, so a client can discover the API through
		// the gateway either way.
		writeGraphQLResponse(w, http.StatusOK, route.GraphQL.Introspect(operation))
		return
	}
	if len(route.Resolvers) > 0 {
		r.serveSyntheticGraphQL(w, req, service, route, state, operation)
		return
	}
	r.forwardGraphQL(w, req, service, state, plan, body, request)
}

// forwardGraphQL sends a validated operation to the backend.
//
// The original body is replayed byte for byte when there is one. Re-encoding
// the decoded request would silently drop `extensions`, which is where Apollo
// puts persisted-query hashes and tracing, and those are members the gateway
// has no business editing.
func (r *Runtime) forwardGraphQL(w http.ResponseWriter, req *http.Request, service *Service, state *policy.State, plan policy.Plan, body []byte, request graphql.Request) {
	if body == nil {
		// A GET carried the query, and GraphQL backends accept POST. Encoding
		// it here keeps `?query=` working against a POST-only backend.
		body = graphql.EncodeRequest(request)
	}
	forwarded := req.Clone(req.Context())
	forwarded.Method = http.MethodPost
	forwarded.Body = io.NopCloser(bytes.NewReader(body))
	forwarded.ContentLength = int64(len(body))
	forwarded.Header = req.Header.Clone()
	forwarded.Header.Set("Content-Type", "application/json")
	forwarded.Header.Del("Content-Length")

	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		r.policyFailure(w, req, plan, state, err)
		return
	}
	response, err := forwardWithRetry(client, forwarded, state.BackendURL, state.Path, plan.Backend)
	if err != nil {
		r.policyFailure(w, req, plan, state, fmt.Errorf("backend request failed: %w", err))
		return
	}
	defer response.Body.Close()
	state.Response = response
	if err := policy.Execute(plan.Outbound, state); err != nil {
		r.policyFailure(w, req, plan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	writeForwardedResponse(w, response, state)
}

func writeGraphQLResponse(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeGraphQLError reports a request error.
//
// The status is 4xx and the body is a GraphQL error list, which is the pairing
// the GraphQL-over-HTTP spec calls a request error: the server never began
// executing. It is deliberately NOT the 200-with-errors shape, which means
// execution ran and some fields failed; returning that for a malformed request
// would tell a client the query was accepted.
func writeGraphQLError(w http.ResponseWriter, status int, body []byte) {
	writeGraphQLResponse(w, status, body)
}
