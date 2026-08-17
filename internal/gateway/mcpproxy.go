package gateway

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
)

// MCP passthrough: putting APIM in front of an MCP server somebody else runs.
//
// This is the OTHER half of the feature, and the difference from exposure is
// where the tools come from. An exposed API's tools are its own operations,
// synthesised here. A passthrough API's tools belong to an upstream server and
// this never sees them: every JSON-RPC message is forwarded, and the answer
// comes back untouched.
//
// Forwarding rather than interpreting is the whole point. An MCP server may
// implement resources, prompts, sampling, completions and revisions of the
// protocol this emulator has never heard of; a proxy that understood the
// messages would silently cap the upstream server at whatever it knew about.

// mcpPassthroughMode is the value that puts an MCP API in front of an upstream
// server instead of synthesising one.
const mcpPassthroughMode = "passthrough"

// isMCPPassthrough reports whether an MCP API proxies an upstream server.
//
// `mcpMode` is THIS EMULATOR'S OWN property, like the rest of the MCP resource
// shape: the preview ARM contract for MCP servers has not been captured here,
// and `docs/parity.md` says so. It is explicit rather than inferred from an API
// having no operations, because "no operations" is also what a misconfigured
// exposure looks like, and the two should not be the same request.
func isMCPPassthrough(document map[string]any) bool {
	properties, _ := document["properties"].(map[string]any)
	mode, _ := properties["mcpMode"].(string)
	return strings.EqualFold(strings.TrimSpace(mode), mcpPassthroughMode)
}

// serveMCPPassthrough forwards one MCP message to the upstream server.
//
// It runs after the inbound and backend policy phases, so subscription keys,
// rate limits, token governance and header rewriting all apply exactly as they
// do for any other API. What it replaces is only the forwarding step -- which
// is the reason to put APIM in front of an MCP server at all.
func (r *Runtime) serveMCPPassthrough(w http.ResponseWriter, req *http.Request, service *Service, state *policy.State, plan policy.Plan) {
	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		gatewayError(w, http.StatusBadGateway, "BackendNotFound", err.Error())
		return
	}
	target := strings.TrimSuffix(state.BackendURL, "/")
	// The upstream endpoint is the backend URL itself: a caller pointing an MCP
	// API at a server gives the server's own MCP endpoint, not a host to append
	// a path to.
	outbound, err := http.NewRequestWithContext(req.Context(), req.Method, target, req.Body)
	if err != nil {
		gatewayError(w, http.StatusBadGateway, "BackendRequestFailed", err.Error())
		return
	}
	// Every request header is carried, because MCP's transport lives in them:
	// `Mcp-Session-Id` identifies the conversation and `Mcp-Protocol-Version`
	// the revision in use. Dropping either turns a working session into a
	// client that reconnects forever.
	copyHeaders(outbound.Header, req.Header)
	copyHeaders(outbound.Header, state.Headers)
	outbound.Header.Del("Host")
	response, err := client.Do(outbound)
	if err != nil {
		gatewayError(w, http.StatusBadGateway, "BackendRequestFailed", err.Error())
		return
	}
	defer response.Body.Close()
	// Outbound policies run, so a caller can add or rewrite response headers in
	// front of an MCP server. What they cannot do here is rewrite the BODY: it
	// may be a stream, and buffering it to edit would turn a streaming tool call
	// into one that appears to hang. A policy that sets a body is honoured as a
	// short-circuit below rather than merged into the upstream's answer.
	state.Response = response
	if err := policy.Execute(plan.Outbound, state); err != nil {
		r.policyFailure(w, req, plan, state, err)
		return
	}
	if state.Returned {
		writePolicyResponse(w, state)
		return
	}
	// And back the other way: the session id the upstream server assigns has to
	// reach the client, or nothing after `initialize` will be accepted.
	copyHeaders(w.Header(), response.Header)
	copyHeaders(w.Header(), state.Headers)
	status := response.StatusCode
	if state.StatusCode != 0 {
		status = state.StatusCode
	}
	w.WriteHeader(status)
	// writeGatewayBody streams a server-sent-event body chunk by chunk, which
	// an MCP server uses for a long-running call. Buffering it would make a
	// streaming tool look like a hung one.
	writeGatewayBody(w, response)
}

// mcpPassthroughRequest reports whether a request should be forwarded rather
// than answered here. A passthrough API forwards every method, including the
// GET that opens the server-to-client stream, because the upstream server may
// have messages to send even though a synthesised one never does.
func mcpPassthroughRequest(route *Route, relative string) bool {
	return route.MCPPassthrough && isMCPRequest(relative)
}
