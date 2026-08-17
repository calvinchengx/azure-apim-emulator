// Package mcp implements the Model Context Protocol surface APIM exposes when
// an API is published as an MCP server.
//
// The protocol here is not inferred from documentation: it was captured from
// the reference client (`@modelcontextprotocol/sdk`) driving a probe server,
// because that is what a real caller will send. What the capture established,
// and what the shapes below encode:
//
//   - one endpoint, POST, with `Accept: application/json, text/event-stream`;
//   - `initialize` first, and the session id the server returns is echoed on
//     every later request as `Mcp-Session-Id`, alongside `Mcp-Protocol-Version`;
//   - `notifications/initialized` carries no id and expects no result;
//   - the client also opens a GET on the same endpoint for server-initiated
//     messages, and tolerates a refusal, which is why this server declines it
//     rather than pretending to hold a stream open.
package mcp

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ProtocolVersions are the revisions this server will speak, newest first.
//
// The client proposes one and the server answers with the version it will
// actually use. Echoing back whatever was proposed would be the dangerous
// direction: a client asking for a revision this does not implement would be
// told it had it.
var ProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

// Request is one JSON-RPC message from a client.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// IsNotification reports whether the message expects no reply. JSON-RPC marks
// that by the absence of an id, not by the method name.
func (r Request) IsNotification() bool { return len(r.ID) == 0 || string(r.ID) == "null" }

// Response is one JSON-RPC reply.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC's reserved codes. Using the right one matters because the reference
// client distinguishes them: a method it never sent is a different failure from
// a tool that refused.
const (
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// Tool is one callable operation advertised to a client.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Schema is the compiled MCP surface of one API.
type Schema struct {
	Name    string
	Version string
	Tools   []Tool
	// byName resolves a tool call without a linear scan, and is what makes an
	// unknown tool a refusal rather than a silent no-op.
	byName map[string]ToolBinding
}

// ToolBinding is how a tool call reaches the API behind it.
type ToolBinding struct {
	Tool        Tool
	Method      string
	URLTemplate string
	// TemplateParams and QueryParams name the arguments that belong in the
	// path and the query string. Anything else declared goes in the body.
	TemplateParams []string
	QueryParams    []string
	AcceptsBody    bool
}

// Lookup finds a tool binding by name.
func (s *Schema) Lookup(name string) (ToolBinding, bool) {
	binding, ok := s.byName[name]
	return binding, ok
}

// NegotiateVersion answers a client's proposed protocol revision.
func NegotiateVersion(proposed string) string {
	for _, version := range ProtocolVersions {
		if version == proposed {
			return version
		}
	}
	// The client asked for something this does not implement, so it is told
	// what it will actually get and may refuse.
	return ProtocolVersions[0]
}

// OperationSource is one APIM operation, reduced to what a tool needs.
type OperationSource struct {
	Name        string
	DisplayName string
	Method      string
	URLTemplate string
	Document    map[string]any
}

// Compile derives an MCP tool surface from an API's operations.
//
// The operations ARE the tools: APIM publishes an API as an MCP server by
// exposing its operations, and the input schema comes from the parameters the
// operation already declares. Deriving it from anything else would mean asking
// an operator to describe the same call twice and letting the two disagree.
func Compile(name, version string, operations []OperationSource) *Schema {
	schema := &Schema{Name: name, Version: version, byName: map[string]ToolBinding{}}
	for _, operation := range operations {
		binding := bindOperation(operation)
		if _, clash := schema.byName[binding.Tool.Name]; clash {
			// APIM operation names are unique within an API, so this cannot
			// happen from the store. Skipping rather than overwriting keeps it
			// that way if it ever does.
			continue
		}
		schema.byName[binding.Tool.Name] = binding
		schema.Tools = append(schema.Tools, binding.Tool)
	}
	sort.Slice(schema.Tools, func(i, j int) bool { return schema.Tools[i].Name < schema.Tools[j].Name })
	return schema
}

func bindOperation(operation OperationSource) ToolBinding {
	properties := map[string]any{}
	var required []string
	binding := ToolBinding{Method: strings.ToUpper(operation.Method), URLTemplate: operation.URLTemplate}

	document, _ := operation.Document["properties"].(map[string]any)
	for _, parameter := range parameterList(document, "templateParameters") {
		// A path parameter is always required, whatever it declares: without it
		// there is no URL, so the declaration is not consulted.
		name, schema, _ := parameterSchema(parameter)
		if name == "" {
			continue
		}
		properties[name] = schema
		binding.TemplateParams = append(binding.TemplateParams, name)
		required = append(required, name)
	}
	// A template placeholder nobody declared is still a parameter the call
	// cannot be made without, so it is advertised rather than silently dropped.
	for _, name := range templatePlaceholders(operation.URLTemplate) {
		if _, known := properties[name]; known {
			continue
		}
		properties[name] = map[string]any{"type": "string", "description": "Path parameter " + name}
		binding.TemplateParams = append(binding.TemplateParams, name)
		required = append(required, name)
	}
	request, _ := document["request"].(map[string]any)
	for _, parameter := range parameterList(request, "queryParameters") {
		name, schema, isRequired := parameterSchema(parameter)
		if name == "" {
			continue
		}
		properties[name] = schema
		binding.QueryParams = append(binding.QueryParams, name)
		if isRequired {
			required = append(required, name)
		}
	}
	if methodAcceptsBody(binding.Method) {
		binding.AcceptsBody = true
		properties["body"] = map[string]any{
			"type":        "string",
			"description": "Request body sent to the operation.",
		}
	}
	sort.Strings(required)
	inputSchema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		inputSchema["required"] = required
	}
	description, _ := document["description"].(string)
	if strings.TrimSpace(description) == "" {
		description = operation.DisplayName
	}
	binding.Tool = Tool{Name: operation.Name, Description: description, InputSchema: inputSchema}
	return binding
}

func parameterList(document map[string]any, key string) []map[string]any {
	raw, _ := document[key].([]any)
	values := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		if parameter, ok := entry.(map[string]any); ok {
			values = append(values, parameter)
		}
	}
	return values
}

func parameterSchema(parameter map[string]any) (string, map[string]any, bool) {
	name, _ := parameter["name"].(string)
	if name == "" {
		return "", nil, false
	}
	schema := map[string]any{"type": jsonType(parameter["type"])}
	if description, ok := parameter["description"].(string); ok && description != "" {
		schema["description"] = description
	}
	required, _ := parameter["required"].(bool)
	return name, schema, required
}

// jsonType maps APIM's parameter type names onto JSON Schema's.
//
// APIM's are OpenAPI-flavoured and mostly already match; the ones that do not
// are mapped rather than passed through, because a client validates arguments
// against this schema and an unknown type name makes every call fail.
func jsonType(value any) string {
	name, _ := value.(string)
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "integer", "int32", "int64", "long":
		return "integer"
	case "number", "double", "float", "decimal":
		return "number"
	case "boolean", "bool":
		return "boolean"
	case "array":
		return "array"
	case "object":
		return "object"
	default:
		return "string"
	}
}

func methodAcceptsBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func templatePlaceholders(template string) []string {
	var names []string
	for {
		open := strings.Index(template, "{")
		if open < 0 {
			return names
		}
		close := strings.Index(template[open:], "}")
		if close < 0 {
			return names
		}
		name := template[open+1 : open+close]
		// APIM allows a format hint after a colon, as in `{id:int}`.
		if colon := strings.Index(name, ":"); colon >= 0 {
			name = name[:colon]
		}
		if name != "" {
			names = append(names, name)
		}
		template = template[open+close+1:]
	}
}

// ResolvePath substitutes a tool call's arguments into the operation's URL
// template and query string.
//
// A template parameter with no argument is an error rather than an empty
// segment: `/orders//items` would reach the backend as a different route and
// most likely 404 there, which is a confusing way to report a missing argument.
func (b ToolBinding) ResolvePath(arguments map[string]any) (string, string, error) {
	path := b.URLTemplate
	for _, name := range b.TemplateParams {
		value, ok := arguments[name]
		if !ok {
			return "", "", fmt.Errorf("missing required argument %q", name)
		}
		path = replacePlaceholder(path, name, argumentString(value))
	}
	query := make([]string, 0, len(b.QueryParams))
	for _, name := range b.QueryParams {
		if value, ok := arguments[name]; ok {
			query = append(query, name+"="+argumentString(value))
		}
	}
	sort.Strings(query)
	return path, strings.Join(query, "&"), nil
}

func replacePlaceholder(path, name, value string) string {
	for _, form := range []string{"{" + name + "}"} {
		path = strings.ReplaceAll(path, form, value)
	}
	// The format-hinted form, `{id:int}`, has to be found by scanning.
	for {
		open := strings.Index(path, "{"+name+":")
		if open < 0 {
			return path
		}
		close := strings.Index(path[open:], "}")
		if close < 0 {
			return path
		}
		path = path[:open] + value + path[open+close+1:]
	}
}

func argumentString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	default:
		// Arguments arrive from JSON, so every value here is already
		// marshalable; an error branch would be unreachable.
		encoded, _ := json.Marshal(typed)
		return strings.Trim(string(encoded), `"`)
	}
}
