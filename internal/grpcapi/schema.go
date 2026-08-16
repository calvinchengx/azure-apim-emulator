// Package grpcapi compiles protobuf service definitions for the gateway.
//
// APIM's gRPC support is pass-through: the API carries a .proto describing the
// services it fronts, and the gateway proxies HTTP/2 gRPC calls to a backend
// that implements them. What the schema buys is the same thing a GraphQL schema
// buys: the gateway can refuse a call to a method the service does not define,
// so the backend never sees it and the caller gets the same answer whichever
// backend is behind the API.
package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"github.com/bufbuild/protocompile/linker"
)

// Schema is a compiled set of protobuf service definitions.
type Schema struct {
	// Proto is the source as imported. The ARM schema resource returns exactly
	// what was uploaded, not a re-print, so a caller comparing what it PUT
	// against what it GETs sees no spurious difference.
	Proto string
	// methods maps a gRPC path (/package.Service/Method) to its descriptor.
	methods map[string]Method
}

// Method is one RPC the schema defines.
type Method struct {
	Service         string
	Name            string
	ClientStreaming bool
	ServerStreaming bool
}

// Path is the HTTP/2 :path a gRPC client uses to call this method.
func (m Method) Path() string { return "/" + m.Service + "/" + m.Name }

// Parse compiles a .proto source into a schema.
//
// Imports are deliberately not resolved from disk: an uploaded schema is a
// single document, and reaching for files would either fail confusingly or read
// something from the emulator's own filesystem. Well-known types are supplied
// from the compiled-in standard imports, which is what a caller referencing
// google/protobuf/empty.proto expects to work.
func Parse(source string) (*Schema, error) {
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("grpc: schema document is empty")
	}
	resolver := protocompile.WithStandardImports(&protocompile.SourceResolver{
		Accessor: protocompile.SourceAccessorFromMap(map[string]string{"schema.proto": source}),
	})
	compiler := protocompile.Compiler{Resolver: resolver, SourceInfoMode: protocompile.SourceInfoNone}
	files, err := compiler.Compile(context.Background(), "schema.proto")
	if err != nil {
		return nil, fmt.Errorf("grpc: %w", err)
	}
	schema := &Schema{Proto: source, methods: map[string]Method{}}
	for _, file := range files {
		collectMethods(file, schema.methods)
	}
	if len(schema.methods) == 0 {
		return nil, errors.New("grpc: schema defines no service methods")
	}
	return schema, nil
}

func collectMethods(file linker.File, into map[string]Method) {
	// Names come from the protobuf reflection API rather than from the parse
	// tree, so a path here is the path a real gRPC client resolves.
	services := file.Services()
	for i := range services.Len() {
		service := services.Get(i)
		methods := service.Methods()
		for j := range methods.Len() {
			method := methods.Get(j)
			entry := Method{
				Service:         string(service.FullName()),
				Name:            string(method.Name()),
				ClientStreaming: method.IsStreamingClient(),
				ServerStreaming: method.IsStreamingServer(),
			}
			into[entry.Path()] = entry
		}
	}
}

// Lookup finds the method a gRPC path addresses.
func (s *Schema) Lookup(path string) (Method, bool) {
	method, ok := s.methods[path]
	return method, ok
}

// Methods lists every RPC in stable order, for diagnostics and tests.
func (s *Schema) Methods() []Method {
	paths := make([]string, 0, len(s.methods))
	for path := range s.methods {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	list := make([]Method, 0, len(paths))
	for _, path := range paths {
		list = append(list, s.methods[path])
	}
	return list
}

// ServiceNames lists the fully-qualified service names the schema defines.
func (s *Schema) ServiceNames() []string {
	seen := map[string]bool{}
	for _, method := range s.methods {
		seen[method.Service] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
