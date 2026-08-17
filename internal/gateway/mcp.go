package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	mcpc "github.com/calvinchengx/azure-apim-emulator/internal/mcp"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// Publishing an API as an MCP server.
//
// The API's operations are its tools. A tool call is turned back into the HTTP
// request that operation already describes and sent to the same backend the
// REST callers reach, so an MCP client and an HTTP client are talking to one
// API rather than to two implementations of it that can drift.

const mcpAPIType = "mcp"

// mcpEndpoint is the path suffix an MCP client posts to, which is what APIM
// appends to the API's own path.
const mcpEndpoint = "/mcp"

func isMCPAPI(api model.API) bool { return strings.EqualFold(apiTypeOf(api), mcpAPIType) }

// mcpSchemaFor compiles an MCP API's operations into a tool surface.
func mcpSchemaFor(api model.API, operations []model.Operation) *mcpc.Schema {
	if !isMCPAPI(api) {
		return nil
	}
	sources := make([]mcpc.OperationSource, 0, len(operations))
	for _, operation := range operations {
		sources = append(sources, mcpc.OperationSource{
			Name:        operation.Name,
			DisplayName: operation.DisplayName,
			Method:      operation.Method,
			URLTemplate: operation.URLTemplate,
			Document:    operation.Document,
		})
	}
	name := api.DisplayName
	if name == "" {
		name = api.Name
	}
	return mcpc.Compile(name, "1.0.0", sources)
}

// isMCPRequest reports whether a request addresses the MCP endpoint.
func isMCPRequest(relative string) bool {
	trimmed := strings.TrimSuffix(relative, "/")
	return strings.EqualFold(trimmed, mcpEndpoint) || trimmed == ""
}

// serveMCP answers the JSON-RPC methods an MCP client sends.
func (r *Runtime) serveMCP(w http.ResponseWriter, req *http.Request, service *Service, route *Route, state *policy.State, plan policy.Plan) {
	// The reference client opens a GET on the same endpoint for
	// server-initiated messages. This server has none to send, and declining is
	// what the capture showed a client tolerates -- holding a stream open that
	// will never carry anything would keep a connection per client for nothing.
	if req.Method == http.MethodGet {
		w.Header().Set("Allow", http.MethodPost)
		gatewayError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "This MCP server sends no server-initiated messages.")
		return
	}
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		gatewayError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "The MCP endpoint accepts POST.")
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		writeMCPError(w, nil, mcpc.CodeInvalidRequest, "the request body could not be read")
		return
	}
	var message mcpc.Request
	if err := json.Unmarshal(body, &message); err != nil {
		writeMCPError(w, nil, mcpc.CodeInvalidRequest, "the request body is not a JSON-RPC message")
		return
	}
	// A notification expects no reply at all, and answering one with a result
	// makes the reference client discard the response and log a protocol error.
	if message.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch message.Method {
	case "initialize":
		r.mcpInitialize(w, message, route)
	case "tools/list":
		writeMCPResult(w, message.ID, map[string]any{"tools": route.MCP.Tools})
	case "tools/call":
		r.mcpCallTool(w, req, service, route, state, plan, message)
	case "ping":
		writeMCPResult(w, message.ID, map[string]any{})
	default:
		writeMCPError(w, message.ID, mcpc.CodeMethodNotFound, "unknown method "+message.Method)
	}
}

func (r *Runtime) mcpInitialize(w http.ResponseWriter, message mcpc.Request, route *Route) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(message.Params, &params)
	// The session id is what the client echoes on every later request. It is
	// opaque and this server keeps no state behind it: the tools come from the
	// published API, which is the same for every caller.
	w.Header().Set("Mcp-Session-Id", store.NewOpaqueID())
	writeMCPResult(w, message.ID, map[string]any{
		"protocolVersion": mcpc.NegotiateVersion(params.ProtocolVersion),
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": route.MCP.Name, "version": route.MCP.Version},
	})
}

func (r *Runtime) mcpCallTool(w http.ResponseWriter, req *http.Request, service *Service, route *Route, state *policy.State, plan policy.Plan, message mcpc.Request) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(message.Params, &params); err != nil {
		writeMCPError(w, message.ID, mcpc.CodeInvalidParams, "the tool call parameters are not an object")
		return
	}
	binding, ok := route.MCP.Lookup(params.Name)
	if !ok {
		// A tool this server never advertised is a protocol-level error, not a
		// tool that failed: the client asked for something that does not exist.
		writeMCPError(w, message.ID, mcpc.CodeInvalidParams, "unknown tool "+params.Name)
		return
	}
	path, query, err := binding.ResolvePath(params.Arguments)
	if err != nil {
		writeMCPError(w, message.ID, mcpc.CodeInvalidParams, err.Error())
		return
	}
	client, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		writeMCPResult(w, message.ID, toolFailure(err.Error()))
		return
	}
	status, responseBody, err := callMCPBackend(req, client, state.BackendURL, binding, path, query, params.Arguments)
	if err != nil {
		// A backend that could not be reached is reported as a FAILED TOOL, not
		// as a broken protocol: the conversation is healthy, the tool is not,
		// and that distinction is what lets a model retry or apologise rather
		// than drop the session.
		writeMCPResult(w, message.ID, toolFailure(err.Error()))
		return
	}
	if status >= 400 {
		writeMCPResult(w, message.ID, toolFailure(fmt.Sprintf("the operation returned %d: %s", status, responseBody)))
		return
	}
	writeMCPResult(w, message.ID, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": responseBody}},
	})
	_ = plan
}

// callMCPBackend performs the HTTP call the tool stands for.
func callMCPBackend(req *http.Request, client *http.Client, backendURL string, binding mcpc.ToolBinding, path, query string, arguments map[string]any) (int, string, error) {
	target := strings.TrimSuffix(backendURL, "/") + path
	if query != "" {
		target += "?" + query
	}
	var payload io.Reader
	if binding.AcceptsBody {
		if body, ok := arguments["body"].(string); ok && body != "" {
			payload = strings.NewReader(body)
		}
	}
	outbound, err := http.NewRequestWithContext(req.Context(), binding.Method, target, payload)
	if err != nil {
		return 0, "", err
	}
	if payload != nil {
		outbound.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(outbound)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, "", err
	}
	return response.StatusCode, string(body), nil
}

// toolFailure is the MCP shape for a tool that ran and did not succeed.
func toolFailure(message string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": message}},
		"isError": true,
	}
}

func writeMCPResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeMCPMessage(w, mcpc.Response{JSONRPC: "2.0", ID: id, Result: result})
}

func writeMCPError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	writeMCPMessage(w, mcpc.Response{JSONRPC: "2.0", ID: id, Error: &mcpc.Error{Code: code, Message: message}})
}

// writeMCPMessage answers with a single JSON-RPC object.
//
// The client accepts `application/json` or `text/event-stream` and this always
// chooses JSON: an SSE frame carrying exactly one message and then closing is
// the same information with more ways to be wrong.
func writeMCPMessage(w http.ResponseWriter, response mcpc.Response) {
	// The result is always this package's own maps and strings, so marshalling
	// cannot fail; an error branch here would be unreachable.
	encoded, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

// apiTypeOf reports an API's declared type.
//
// TWO NAMES, AND THE REASON IS MEASURED RATHER THAN GUESSED. Azure's REST
// contract carries this as `properties.type`, which is what Microsoft's own
// SDK puts on the wire: its client-side field is called `apiType` and
// serializes to `type`. Raw ARM callers, and this emulator's own WSDL import,
// have historically written `apiType` instead.
//
// Reading only `apiType` -- which every protocol family here did until the MCP
// witness drove an API through the official SDK -- means an API created by that
// SDK is stored, echoed back on GET looking perfect, and then treated at
// runtime as though it had no type at all. There is no local symptom: the
// round-trip is lossless and only the behaviour is missing.
func apiTypeOf(api model.API) string {
	properties, _ := api.Document["properties"].(map[string]any)
	if value, ok := properties["type"].(string); ok && value != "" {
		return value
	}
	value, _ := properties["apiType"].(string)
	return value
}
