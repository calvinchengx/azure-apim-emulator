package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/expression"
	"github.com/calvinchengx/azure-apim-emulator/internal/graphql"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// maxResolverBodyBytes caps what one resolver may pull back. A synthetic
// GraphQL query can fan out into many resolver calls, so an unbounded read per
// field turns one request into unbounded memory.
const maxResolverBodyBytes = 8 << 20

// resolverKey addresses a resolver by the schema coordinate it binds to.
// Lower-cased because Azure treats the resource name case-insensitively, while
// GraphQL type and field names are case-sensitive; the map key is an internal
// lookup, and the schema has already validated the caller's casing.
func resolverKey(typeName, fieldName string) string {
	return strings.ToLower(typeName + "." + fieldName)
}

// compiledResolver is one resolver plus its compiled data source.
type compiledResolver struct {
	resolver   model.APIResolver
	dataSource policy.DataSource
}

// graphQLResolversFor compiles an API's resolvers.
//
// A resolver whose policy does not compile is an error rather than a skip: a
// missing resolver does not fail loudly, it returns null for its field, and the
// author would be left reading a null they cannot explain.
func graphQLResolversFor(st *store.Store, api model.API, schema *graphql.Schema) (map[string]compiledResolver, error) {
	if schema == nil {
		return nil, nil
	}
	resolvers, err := st.ListAPIResolvers(api.ID())
	if err != nil {
		return nil, err
	}
	if len(resolvers) == 0 {
		return nil, nil
	}
	compiled := map[string]compiledResolver{}
	types := schema.Types()
	for _, resolver := range resolvers {
		// The coordinate must exist in the schema. A resolver bound to a field
		// the schema does not define can never run, and finding that out at
		// import time is the difference between a clear error and a field that
		// is silently always null.
		owner, ok := types[resolver.Type]
		if !ok {
			return nil, fmt.Errorf("resolver %s binds unknown type %q", resolver.ID(), resolver.Type)
		}
		if owner.Fields.ForName(resolver.Field) == nil {
			return nil, fmt.Errorf("resolver %s binds unknown field %q on %q", resolver.ID(), resolver.Field, resolver.Type)
		}
		document, err := st.GetPolicy(resolver.ID())
		if err != nil {
			return nil, fmt.Errorf("resolver %s has no policy: %w", resolver.ID(), err)
		}
		dataSource, err := policy.CompileHTTPDataSource(document.Value)
		if err != nil {
			return nil, fmt.Errorf("resolver %s: %w", resolver.ID(), err)
		}
		compiled[resolverKey(resolver.Type, resolver.Field)] = compiledResolver{resolver: resolver, dataSource: dataSource}
	}
	return compiled, nil
}

// serveSyntheticGraphQL answers an operation from resolvers, with no GraphQL
// backend behind the API at all.
func (r *Runtime) serveSyntheticGraphQL(w http.ResponseWriter, req *http.Request, service *Service, route *Route, state *policy.State, operation *graphql.Operation) {
	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		r.policyFailure(w, req, route.Plan, state, err)
		return
	}
	has := func(typeName, fieldName string) bool {
		_, ok := route.Resolvers[resolverKey(typeName, fieldName)]
		return ok
	}
	resolve := func(typeName, fieldName string, arguments, parent map[string]any) (any, error) {
		entry := route.Resolvers[resolverKey(typeName, fieldName)]
		// A per-field state: the resolver's expressions must see THIS field's
		// arguments. Sharing one state would leak the previous field's
		// arguments into the next, which is a data-disclosure bug, not just a
		// wrong value.
		fieldState := *state
		fieldState.GraphQL = &expression.GraphQLContext{Arguments: arguments, Parent: parent}
		request, err := entry.dataSource.BuildRequest(&fieldState)
		if err != nil {
			return nil, err
		}
		state.Trace("graphql-resolver", typeName+"."+fieldName)
		response, err := client.Do(request.WithContext(req.Context()))
		if err != nil {
			return nil, fmt.Errorf("resolver %s.%s: %w", typeName, fieldName, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxResolverBodyBytes))
		if err != nil {
			return nil, fmt.Errorf("resolver %s.%s: %w", typeName, fieldName, err)
		}
		if response.StatusCode >= 400 {
			// The status is named rather than the body echoed. A backend error
			// page is not part of the GraphQL schema, and pasting it into the
			// errors list hands the caller whatever the backend chose to say.
			return nil, fmt.Errorf("resolver %s.%s: backend returned %d", typeName, fieldName, response.StatusCode)
		}
		if len(body) == 0 {
			return nil, nil
		}
		var value any
		if err := json.Unmarshal(body, &value); err != nil {
			return nil, fmt.Errorf("resolver %s.%s: backend response is not JSON: %w", typeName, fieldName, err)
		}
		return value, nil
	}
	// 200 even when the errors list is non-empty: execution ran, and partial
	// data with per-field errors is the contract GraphQL clients rely on.
	writeGraphQLResponse(w, http.StatusOK, route.GraphQL.Execute(operation, resolve, has))
}
