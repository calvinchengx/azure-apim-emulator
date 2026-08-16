package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	soapc "github.com/calvinchengx/azure-apim-emulator/internal/soap"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// soapAPIType is the value of `properties.apiType` that marks a SOAP API. Azure
// stamps it on any API imported from a WSDL.
const soapAPIType = "soap"

func isSOAPAPI(api model.API) bool {
	properties, _ := api.Document["properties"].(map[string]any)
	apiType, _ := properties["apiType"].(string)
	return strings.EqualFold(apiType, soapAPIType)
}

// soapSchemaFor compiles the WSDL of a SOAP API.
//
// The WSDL lives in the API's retained import definition rather than a schema
// sub-resource, because that is where Azure puts it: SOAP is imported through
// `format: "wsdl"` on the API itself. Reading it from anywhere else would mean
// inventing a resource shape no Azure user could target.
func soapSchemaFor(st *store.Store, api model.API) (*soapc.Schema, error) {
	if !isSOAPAPI(api) {
		return nil, nil
	}
	definition, err := st.GetAPIDefinition(api.ID())
	if err != nil {
		// A SOAP API awaiting its import is not an error, for the same reason a
		// GraphQL API awaiting its schema is not: the caller may still be
		// mid-import, and refusing would make the documented order impossible.
		return nil, nil
	}
	if !isWSDLDefinition(definition.Format) {
		return nil, nil
	}
	compiled, err := soapc.Parse(definition.Value)
	if err != nil {
		return nil, fmt.Errorf("API %s: %w", api.ID(), err)
	}
	return compiled, nil
}

func isWSDLDefinition(format string) bool {
	return strings.EqualFold(format, "wsdl") || strings.EqualFold(format, "wsdl-link")
}

// isSOAPRequest reports whether a request carries a SOAP envelope.
//
// Content type is the signal, not the API type: a SOAP API's WSDL is fetched
// with a plain GET, and answering that with a SOAP fault would be nonsense.
func isSOAPRequest(req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	contentType := strings.ToLower(req.Header.Get("Content-Type"))
	return strings.Contains(contentType, "text/xml") ||
		strings.Contains(contentType, "application/soap+xml") ||
		strings.Contains(contentType, "application/xml")
}

// serveSOAP proxies a SOAP call to the backend.
//
// It runs after the inbound and backend policy phases, so subscription keys,
// rate limits and backend selection behave as they do for any other API. What
// it adds is the contract check and, when that fails, a SOAP FAULT rather than
// an HTTP error, because a fault is what a SOAP client's stack decodes into an
// exception a caller can act on.
func (r *Runtime) serveSOAP(w http.ResponseWriter, req *http.Request, service *Service, route *Route, state *policy.State, plan policy.Plan) {
	version := soapc.DetectVersion(req.Header.Get("Content-Type"))
	action := soapc.Action(req.Header.Get("Content-Type"), req.Header.Get("SOAPAction"))
	element, body, err := soapc.BodyElement(req.Body)
	if err != nil {
		writeSOAPFault(w, version, "Client", err.Error())
		return
	}
	operation, ok := route.SOAP.Lookup(action, element)
	if !ok {
		// Refused here rather than forwarded, exactly as an unknown GraphQL
		// field or gRPC method is. The name in the message is whichever
		// identifier the caller actually used, so the error points at what they
		// wrote rather than at an empty string.
		named := action
		if named == "" {
			named = element
		}
		writeSOAPFault(w, version, "Client", "the service defines no operation "+named)
		return
	}
	state.Trace("soap", operation.Name)

	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		r.policyFailure(w, req, plan, state, err)
		return
	}
	// The envelope is replayed byte for byte. Re-serialising the parsed
	// document would change whitespace, prefixes and attribute order, and a
	// WS-Security signed envelope would stop verifying.
	forwarded := req.Clone(req.Context())
	forwarded.Body = io.NopCloser(bytes.NewReader(body))
	forwarded.ContentLength = int64(len(body))
	forwarded.Header = req.Header.Clone()
	forwarded.Header.Del("Content-Length")

	response, err := forwardWithRetry(client, forwarded, state.BackendURL, state.Path, plan.Backend)
	if err != nil {
		writeSOAPFault(w, version, "Server", "backend request failed: "+err.Error())
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

// writeSOAPFault answers a call the gateway is refusing itself.
func writeSOAPFault(w http.ResponseWriter, version soapc.Version, code, message string) {
	body, contentType, status := soapc.Fault(version, code, message)
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
