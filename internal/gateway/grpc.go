package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/calvinchengx/azure-apim-emulator/internal/grpcapi"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/policy"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
	"golang.org/x/net/http2"
)

// GRPCSchemaContentType is the content type Azure gives a protobuf schema
// resource under an API. It rides the same `/apis/{id}/schemas/{name}` resource
// every other schema uses; only this discriminator says which one is protobuf.
const GRPCSchemaContentType = "application/vnd.ms-azure-apim.grpc.schema"

// grpcAPIType is the value of `properties.apiType` that marks a gRPC API.
const grpcAPIType = "grpc"

// gRPC status codes used by the gateway itself. The full set lives in the gRPC
// spec; these are the ones a proxy can legitimately originate.
const (
	grpcStatusUnimplemented = "12"
	grpcStatusUnavailable   = "14"
	grpcStatusInternal      = "13"
)

// isGRPCRequest reports whether a request is gRPC traffic.
//
// The content type is the signal, not the API type, because a gRPC API's own
// health or reflection probes may arrive as plain HTTP and must not be framed
// as gRPC responses.
func isGRPCRequest(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Content-Type"), "application/grpc")
}

func isGRPCAPI(api model.API) bool { return strings.EqualFold(apiTypeOf(api), grpcAPIType) }

// grpcSchemaFor compiles the protobuf schema of a gRPC API, and returns nil for
// anything else. Same pairing rule as GraphQL: an apiType with no schema
// describes nothing servable, and a protobuf schema on a REST API is a document
// the gateway must not act on. A gRPC API awaiting its schema is not an error,
// because ARM creates the API and its schema as separate resources.
func grpcSchemaFor(st *store.Store, api model.API) (*grpcapi.Schema, error) {
	if !isGRPCAPI(api) {
		return nil, nil
	}
	schemas, err := st.ListAPISchemas(api.ID())
	if err != nil {
		return nil, err
	}
	for _, schema := range schemas {
		if !strings.EqualFold(schema.ContentType, GRPCSchemaContentType) {
			continue
		}
		source, _ := schema.Document["value"].(string)
		compiled, err := grpcapi.Parse(source)
		if err != nil {
			return nil, fmt.Errorf("API %s: %w", api.ID(), err)
		}
		return compiled, nil
	}
	return nil, nil
}

// serveGRPC proxies a gRPC call to the backend.
//
// It runs after the inbound and backend policy phases, so subscription keys,
// rate limits and backend selection behave as they do for any other API. What
// it replaces is the forwarding step, because gRPC needs three things a plain
// proxy does not do: HTTP/2 end to end, a streamed body in both directions, and
// TRAILERS, which is where gRPC puts the call's status.
func (r *Runtime) serveGRPC(w http.ResponseWriter, req *http.Request, service *Service, route *Route, state *policy.State, plan policy.Plan) {
	// HTTP/1.1 cannot carry trailers, so a gRPC call that arrived over it could
	// never be answered correctly. Saying so is better than proxying and
	// leaving the client waiting for a status that can never come.
	if !req.ProtoAtLeast(2, 0) {
		writeGRPCStatus(w, grpcStatusInternal, "gRPC requires HTTP/2; this connection negotiated "+req.Proto)
		return
	}
	if method, ok := route.GRPC.Lookup(req.URL.Path); !ok {
		// Refused here rather than forwarded, exactly as an invalid GraphQL
		// query is. UNIMPLEMENTED is the status a gRPC server returns for a
		// method it does not have, so the client sees the same error it would
		// from the backend itself.
		writeGRPCStatus(w, grpcStatusUnimplemented, "unknown method "+req.URL.Path)
		return
	} else {
		state.Trace("grpc", method.Path())
	}

	base, err := backendHTTPClient(r.client, service, state.BackendID)
	if err != nil {
		r.policyFailure(w, req, plan, state, err)
		return
	}
	client := grpcClient(base, state.BackendURL)
	target, err := grpcBackendURL(state.BackendURL, req.URL.Path, req.URL.RawQuery)
	if err != nil {
		writeGRPCStatus(w, grpcStatusInternal, err.Error())
		return
	}
	// The body is passed through unread. A gRPC message stream must not be
	// buffered: a server-streaming call can run for as long as it likes, and
	// reading it whole would hold the whole stream in memory and defer every
	// message until the call ended.
	forwarded, err := http.NewRequestWithContext(req.Context(), req.Method, target, req.Body)
	if err != nil {
		writeGRPCStatus(w, grpcStatusInternal, err.Error())
		return
	}
	forwarded.Header = req.Header.Clone()
	// Hop-by-hop headers are HTTP/1.1 concepts that HTTP/2 forbids outright.
	forwarded.Header.Del("Connection")
	forwarded.Header.Del("Keep-Alive")
	forwarded.Header.Del("Transfer-Encoding")
	forwarded.Header.Del("Upgrade")
	forwarded.ContentLength = -1

	response, err := client.Do(forwarded)
	if err != nil {
		writeGRPCStatus(w, grpcStatusUnavailable, "backend request failed: "+err.Error())
		return
	}
	defer response.Body.Close()
	r.writeGRPCResponse(w, response)
}

// writeGRPCResponse copies a backend gRPC response, headers, streamed body and
// trailers alike.
func (r *Runtime) writeGRPCResponse(w http.ResponseWriter, response *http.Response) {
	header := w.Header()
	for name, values := range response.Header {
		for _, value := range values {
			header.Add(name, value)
		}
	}
	// Trailers must be ANNOUNCED before the body is written; net/http has no
	// way to add one afterwards otherwise. The backend tells us which ones to
	// expect in its own Trailer header, and gRPC's status lives there, so an
	// unannounced trailer is a call the client can never see the result of.
	announced := trailerNames(response)
	for _, name := range announced {
		header.Add("Trailer", name)
	}
	w.WriteHeader(response.StatusCode)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		// Flush the headers so a streaming client sees them before the first
		// message rather than only when the stream ends.
		flusher.Flush()
	}
	copyGRPCBody(w, response.Body, flusher)
	for name, values := range response.Trailer {
		for _, value := range values {
			header.Add(http.TrailerPrefix+name, value)
		}
	}
}

// copyGRPCBody streams the body through, flushing each chunk so a
// server-streaming call delivers messages as they arrive instead of at the end.
func copyGRPCBody(w io.Writer, body io.Reader, flusher http.Flusher) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// trailerNames lists the trailers a response declares.
//
// Go moves trailers it saw announced into Response.Trailer, but a gRPC server
// may send trailers it never announced (the common "Trailers-Only" reply does
// exactly that), so both sources are merged.
func trailerNames(response *http.Response) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" || seen[canonical] {
			return
		}
		seen[canonical] = true
		names = append(names, canonical)
	}
	for _, value := range response.Header.Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			add(name)
		}
	}
	// SORTED, because ranging a map is randomised in Go and this list becomes
	// the wire's Trailer header. The set is what matters to a client, but
	// emitting it in a different order on every response is a difference
	// callers can see, and it made a test that read only the first announced
	// name fail roughly one run in ten.
	declared := make([]string, 0, len(response.Trailer))
	for name := range response.Trailer {
		declared = append(declared, name)
	}
	sort.Strings(declared)
	for _, name := range declared {
		add(name)
	}
	// grpc-status is what carries success or failure. Announcing it even when
	// the backend forgot to means a client is never left waiting on a status
	// that would otherwise be dropped.
	add("Grpc-Status")
	add("Grpc-Message")
	return names
}

// grpcBackendURL joins the backend base with the gRPC method path.
func grpcBackendURL(backend, path, query string) (string, error) {
	if backend == "" {
		return "", fmt.Errorf("gRPC API has no backend URL")
	}
	target := strings.TrimRight(backend, "/") + path
	if query != "" {
		target += "?" + query
	}
	return target, nil
}

// writeGRPCStatus answers a call the gateway is refusing itself.
//
// The HTTP status is 200 and the gRPC status rides in the headers. That pairing
// is the gRPC spec's: a non-200 makes clients report a transport failure rather
// than the status code we are trying to communicate, so the caller would see
// "connection error" instead of "unknown method".
func writeGRPCStatus(w http.ResponseWriter, code, message string) {
	header := w.Header()
	header.Set("Content-Type", "application/grpc")
	header.Set("Grpc-Status", code)
	header.Set("Grpc-Message", grpcPercentEncode(message))
	w.WriteHeader(http.StatusOK)
}

// grpcPercentEncode escapes a status message for the wire.
//
// grpc-message is an HTTP header carrying arbitrary text, and the spec defines a
// percent-encoding for bytes a header cannot hold. Sending them raw makes a
// strict HTTP/2 client reject the whole response, turning a clear error message
// into a protocol failure.
func grpcPercentEncode(message string) string {
	var builder strings.Builder
	for i := 0; i < len(message); i++ {
		c := message[i]
		if c < 0x20 || c > 0x7E || c == '%' {
			fmt.Fprintf(&builder, "%%%02X", c)
			continue
		}
		builder.WriteByte(c)
	}
	return builder.String()
}

// grpcClient produces a client that speaks HTTP/2 to the backend.
//
// This is the outbound mirror of the inbound requirement, and it is not
// automatic. Go's default transport negotiates HTTP/2 only over TLS, so a
// cleartext gRPC backend gets an HTTP/1.1 request and answers with HTTP/2
// frames the transport then reports as a malformed response. h2c has to be
// asked for explicitly.
//
// A transport the caller already configured (client certificates, a pinned
// CA) is preserved: its TLS config is carried onto the HTTP/2 transport rather
// than replaced, so a backend requiring mutual TLS still works over gRPC.
func grpcClient(base *http.Client, backend string) *http.Client {
	transport := &http2.Transport{}
	if existing, ok := base.Transport.(*http.Transport); ok && existing.TLSClientConfig != nil {
		transport.TLSClientConfig = existing.TLSClientConfig.Clone()
	}
	if strings.HasPrefix(strings.ToLower(backend), "http://") {
		// AllowHTTP lets the transport use the h2c prior-knowledge handshake,
		// and DialTLSContext must then make a PLAIN connection: the field is
		// consulted for every dial, so leaving it nil would attempt TLS
		// against a cleartext port.
		transport.AllowHTTP = true
		transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, addr)
		}
	}
	return &http.Client{Transport: transport, Timeout: base.Timeout}
}
