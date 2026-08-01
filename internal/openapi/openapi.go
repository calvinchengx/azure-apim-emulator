// Package openapi compiles OpenAPI documents into APIM resource inputs.
package openapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"gopkg.in/yaml.v3"
)

// Document is the validated, normalized result of an OpenAPI import.
type Document struct {
	Version     string
	Title       string
	Description string
	ServiceURL  string
	Operations  []model.Operation
	Schemas     map[string]any
	Raw         map[string]any
}

// Export renders canonical API resources as OpenAPI 3 YAML/JSON or Swagger 2 JSON.
func Export(api model.API, operations []model.Operation, schemas map[string]any, format string) ([]byte, string, string, error) {
	paths := map[string]any{}
	for _, operation := range operations {
		pathItem, _ := paths[operation.URLTemplate].(map[string]any)
		if pathItem == nil {
			pathItem = map[string]any{}
			paths[operation.URLTemplate] = pathItem
		}
		pathItem[strings.ToLower(operation.Method)] = map[string]any{
			"operationId": operation.Name, "summary": operation.DisplayName,
			"responses": map[string]any{"default": map[string]any{"description": "Default response"}},
		}
	}
	info := map[string]any{"title": api.DisplayName, "version": "1.0"}
	var document map[string]any
	resultFormat, contentType := "", ""
	switch format {
	case "openapi-link", "openapi+json-link":
		document = map[string]any{"openapi": "3.0.3", "info": info, "paths": paths}
		if api.ServiceURL != "" {
			document["servers"] = []any{map[string]any{"url": api.ServiceURL}}
		}
		if len(schemas) != 0 {
			document["components"] = map[string]any{"schemas": schemas}
		}
		resultFormat = "openapi-link"
		if format == "openapi-link" {
			value, err := yaml.Marshal(document)
			return value, resultFormat, "application/yaml", err
		}
		contentType = "application/json"
	case "swagger-link":
		document = map[string]any{"swagger": "2.0", "info": info, "paths": paths, "schemes": []any{"https"}}
		if parsed, err := url.Parse(api.ServiceURL); err == nil && parsed.Host != "" {
			document["host"], document["basePath"] = parsed.Host, parsed.Path
			if parsed.Scheme != "" {
				document["schemes"] = []any{parsed.Scheme}
			}
		}
		if len(schemas) != 0 {
			document["definitions"] = schemas
		}
		resultFormat, contentType = "swagger-link-json", "application/json"
	default:
		return nil, "", "", fmt.Errorf("unsupported export format %q", format)
	}
	value, err := json.Marshal(document)
	return value, resultFormat, contentType, err
}

var methods = map[string]bool{
	"delete": true, "get": true, "head": true, "options": true,
	"patch": true, "post": true, "put": true, "trace": true,
}

// Parse validates and normalizes an OpenAPI 2.0 or 3.x JSON/YAML document.
func Parse(source string) (Document, error) {
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(source), &raw); err != nil {
		return Document{}, fmt.Errorf("parse OpenAPI document: %w", err)
	}
	if raw == nil {
		return Document{}, errors.New("OpenAPI document must be an object")
	}
	version, swagger := stringValue(raw, "openapi"), stringValue(raw, "swagger")
	if !strings.HasPrefix(version, "3.") && swagger != "2.0" {
		return Document{}, errors.New("document must declare OpenAPI 3.x or Swagger 2.0")
	}
	if swagger == "2.0" {
		version = swagger
	}
	info, _ := raw["info"].(map[string]any)
	result := Document{Version: version, Title: stringValue(info, "title"), Description: stringValue(info, "description"), Raw: raw, Schemas: map[string]any{}}
	if result.Title == "" {
		return Document{}, errors.New("info.title is required")
	}
	if version == "2.0" {
		result.ServiceURL = swaggerServiceURL(raw)
		if definitions, ok := raw["definitions"].(map[string]any); ok {
			result.Schemas = definitions
		}
	} else {
		result.ServiceURL = openAPIServiceURL(raw)
		if components, ok := raw["components"].(map[string]any); ok {
			if schemas, ok := components["schemas"].(map[string]any); ok {
				result.Schemas = schemas
			}
		}
	}
	paths, ok := raw["paths"].(map[string]any)
	if !ok {
		return Document{}, errors.New("paths must be an object")
	}
	used := map[string]bool{}
	pathNames := make([]string, 0, len(paths))
	for path := range paths {
		pathNames = append(pathNames, path)
	}
	sort.Strings(pathNames)
	for _, path := range pathNames {
		if path == "" || path[0] != '/' {
			return Document{}, fmt.Errorf("path %q must begin with '/'", path)
		}
		pathItem, ok := paths[path].(map[string]any)
		if !ok {
			return Document{}, fmt.Errorf("path %q must be an object", path)
		}
		methodNames := make([]string, 0)
		for method := range pathItem {
			method = strings.ToLower(method)
			if methods[method] {
				methodNames = append(methodNames, method)
			}
		}
		sort.Strings(methodNames)
		for _, method := range methodNames {
			operation, ok := pathItem[method].(map[string]any)
			if !ok {
				return Document{}, fmt.Errorf("operation %s %s must be an object", strings.ToUpper(method), path)
			}
			if value, exists := operation["operationId"]; exists {
				if _, ok := value.(string); !ok {
					return Document{}, fmt.Errorf("operationId for %s %s must be a string", strings.ToUpper(method), path)
				}
			}
			if value, exists := operation["summary"]; exists {
				if _, ok := value.(string); !ok {
					return Document{}, fmt.Errorf("summary for %s %s must be a string", strings.ToUpper(method), path)
				}
			}
			name := stringValue(operation, "operationId")
			if name == "" {
				name = generatedOperationID(method, path)
			}
			baseName := name
			for suffix := 2; used[strings.ToLower(name)]; suffix++ {
				name = fmt.Sprintf("%s-%d", baseName, suffix)
			}
			used[strings.ToLower(name)] = true
			displayName := stringValue(operation, "summary")
			if displayName == "" {
				displayName = name
			}
			result.Operations = append(result.Operations, model.Operation{Name: name, DisplayName: displayName, Method: strings.ToUpper(method), URLTemplate: path})
		}
	}
	return result, nil
}

// JSON returns the normalized document as deterministic JSON.
func (d Document) JSON() (string, error) {
	value, err := json.Marshal(d.Raw)
	return string(value), err
}

func openAPIServiceURL(raw map[string]any) string {
	servers, _ := raw["servers"].([]any)
	if len(servers) == 0 {
		return ""
	}
	server, _ := servers[0].(map[string]any)
	return stringValue(server, "url")
}

func swaggerServiceURL(raw map[string]any) string {
	host := stringValue(raw, "host")
	if host == "" {
		return ""
	}
	scheme := "https"
	if schemes, ok := raw["schemes"].([]any); ok && len(schemes) != 0 {
		if value, ok := schemes[0].(string); ok && value != "" {
			scheme = value
		}
	}
	result := &url.URL{Scheme: scheme, Host: host, Path: stringValue(raw, "basePath")}
	return strings.TrimSuffix(result.String(), "/")
}

func generatedOperationID(method, path string) string {
	name := strings.Trim(path, "/")
	replacer := strings.NewReplacer("/", "-", "{", "", "}", "", "_", "-")
	name = replacer.Replace(name)
	if name == "" {
		name = "root"
	}
	return method + "-" + name
}

func stringValue(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}
