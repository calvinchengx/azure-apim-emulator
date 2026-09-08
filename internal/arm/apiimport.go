package arm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	openapic "github.com/calvinchengx/azure-apim-emulator/internal/openapi"
	soapc "github.com/calvinchengx/azure-apim-emulator/internal/soap"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

const maxImportBytes = 4 << 20

// guardImportHost mitigates SSRF on the linked-import feature: it blocks
// fetching an API definition from a link-local / cloud-metadata address (the
// classic target, e.g. 169.254.169.254), while still allowing loopback and
// private hosts, which are normal when importing from a nearby backend during
// local development. It resolves the host and rejects if any resolved address
// is link-local, multicast, or unspecified. (Import-from-link is a first-class
// Azure APIM feature that inherently fetches an operator-supplied URL; this
// removes the dangerous targets without disabling the feature.)
// lookupIP resolves a hostname to IPs; a package var so tests can drive the
// resolution-failure branch deterministically without depending on real DNS.
var lookupIP = net.LookupIP

func guardImportHost(host string) error {
	if host == "" {
		return errors.New("linked API definition URL has no host")
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		resolved, err := lookupIP(host)
		if err != nil {
			return fmt.Errorf("linked API definition host %q could not be resolved", host)
		}
		ips = resolved
	}
	for _, ip := range ips {
		if importAddressBlocked(ip) {
			return errors.New("linked API definition host is not allowed (link-local or metadata address)")
		}
	}
	return nil
}

// importAddressBlocked reports whether an IP is a forbidden SSRF target for the
// linked-import fetch: link-local (169.254.0.0/16, fe80::/10 — covers the
// 169.254.169.254 cloud-metadata endpoint), multicast, or the unspecified
// address. Loopback and private ranges stay allowed, since importing from a
// nearby backend is normal in local development.
func importAddressBlocked(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// newImportClient builds the HTTP client used to fetch linked API definitions.
// guardImportHost checks the host before the request, but that is a
// time-of-check/time-of-use gap: DNS can rebind between the check and the
// dial, resolving to a blocked address on the actual connection. The Control
// hook runs after resolution, immediately before connect, on the real
// destination IP — so it closes that gap regardless of what DNS returns.
func newImportClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: importDialControl}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}
}

// importDialControl is the net.Dialer.Control hook for the import client: it
// runs on the resolved destination immediately before connect and refuses a
// blocked SSRF target, closing the DNS-rebind gap. Split out (rather than an
// inline closure) so every branch is directly testable — a real dial always
// supplies host:port, so the malformed-address path is otherwise unreachable.
func importDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || importAddressBlocked(ip) {
		return errors.New("linked API definition host is not allowed (link-local or metadata address)")
	}
	return nil
}

func (h *Handler) resolveImport(r *http.Request, format, value string) (string, string, error) {
	linked := format == "openapi-link" || format == "openapi+json-link" || format == "swagger-link-json" ||
		strings.EqualFold(format, "wsdl-link")
	if !linked {
		if format != "openapi" && format != "openapi+json" && format != "swagger-json" && !strings.EqualFold(format, "wsdl") {
			return "", "", fmt.Errorf("unsupported import format %q", format)
		}
		if len(value) > maxImportBytes {
			return "", "", errors.New("API definition exceeds the 4 MiB import limit")
		}
		return value, "", nil
	}
	sourceURL, err := url.Parse(value)
	if err != nil || (sourceURL.Scheme != "http" && sourceURL.Scheme != "https") || sourceURL.Host == "" {
		return "", "", errors.New("linked API definition must be an absolute HTTP or HTTPS URL")
	}
	if err := guardImportHost(sourceURL.Hostname()); err != nil {
		return "", "", err
	}
	client := h.ImportClient
	if client == nil {
		client = newImportClient()
	}
	request, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, sourceURL.String(), nil)
	response, err := client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("retrieve linked API definition: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("linked API definition returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxImportBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("read linked API definition: %w", err)
	}
	if len(content) > maxImportBytes {
		return "", "", errors.New("API definition exceeds the 4 MiB import limit")
	}
	return string(content), sourceURL.String(), nil
}

func (h *Handler) renderAPIExport(api model.API, format string) ([]byte, string, string, error) {
	operations, err := h.Store.ListOperations(api.ID())
	if err != nil {
		return nil, "", "", err
	}
	schemas, err := h.Store.ListAPISchemas(api.ID())
	if err != nil {
		return nil, "", "", err
	}
	definitions := map[string]any{}
	for _, schema := range schemas {
		if schema.Name != "openapi" {
			continue
		}
		if values, ok := schema.Document["components"].(map[string]any); ok {
			definitions = values
		}
		if values, ok := schema.Document["definitions"].(map[string]any); ok {
			definitions = values
		}
	}
	return openapic.Export(api, operations, definitions, format)
}

func (h *Handler) exportSignature(apiID, format string, expires int64) string {
	key := h.ExportKey
	if len(key) == 0 {
		key = []byte("azure-apim-emulator-local-export")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%d", strings.ToLower(apiID), format, expires)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) revisionSource(id string) (model.API, string, error) {
	value, err := h.Store.GetAPI(id)
	if errors.Is(err, store.ErrNotFound) && strings.HasSuffix(strings.ToLower(id), ";rev=1") {
		id = id[:len(id)-6]
		value, err = h.Store.GetAPI(id)
	}
	return value, id, err
}

// isGraphQLAPIDocument reports whether an API payload declares the graphql type.
//
// Both spellings are accepted: `type` is the wire name Azure's contract uses
// and what Microsoft's SDK sends, `apiType` is what raw ARM callers here have
// written. Accepting only one silently ignores half the callers.
func isGraphQLAPIDocument(document map[string]any) bool {
	properties, _ := document["properties"].(map[string]any)
	declared, _ := properties["type"].(string)
	if declared == "" {
		declared, _ = properties["apiType"].(string)
	}
	return strings.EqualFold(declared, "graphql")
}

// isWSDLFormat reports whether an import format carries a WSDL document.
func isWSDLFormat(format string) bool {
	return strings.EqualFold(format, "wsdl") || strings.EqualFold(format, "wsdl-link")
}

// markSOAPAPIType stamps the soap type on an imported WSDL API, which is what
// Azure does and what puts the API on the gateway's SOAP path.
//
// Stamped as `type`, the name Azure's REST contract uses, so a caller reading
// the API back with Microsoft's SDK sees the type it expects. Stamping the
// emulator's older `apiType` spelling instead left an imported SOAP API
// reporting no type at all to that SDK.
func markSOAPAPIType(document map[string]any) {
	properties, ok := document["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		document["properties"] = properties
	}
	properties["type"] = "soap"
}

// wsdlOperations renders a WSDL's operations as APIM operations.
//
// Every SOAP operation is a POST to the same URL; the operation is chosen by
// SOAPAction or by the body element, not by the path. Giving them distinct
// URL templates would invent a REST shape the WSDL does not describe.
func wsdlOperations(schema *soapc.Schema) []model.Operation {
	operations := make([]model.Operation, 0)
	for _, operation := range schema.Operations() {
		operations = append(operations, model.Operation{
			Name: operation.Name, DisplayName: operation.Name,
			Method: http.MethodPost, URLTemplate: "/",
			Document: map[string]any{"properties": map[string]any{"soapAction": operation.Action}},
		})
	}
	return operations
}
