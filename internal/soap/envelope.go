package soap

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// MaxEnvelopeBytes bounds an envelope the gateway inspects. It only needs the
// first body element to route, so a cap here costs nothing and keeps a hostile
// or runaway document from being buffered whole.
const MaxEnvelopeBytes = 1 << 20

// Version is the SOAP version a request used. It decides how the action is
// carried, what content type the answer takes, and what a fault looks like, so
// answering a 1.2 caller with a 1.1 fault produces something their stack cannot
// parse.
type Version int

const (
	// Version11 is SOAP 1.1: text/xml, action in the SOAPAction header.
	Version11 Version = iota
	// Version12 is SOAP 1.2: application/soap+xml, action as a content-type
	// parameter.
	Version12
)

// DetectVersion reads the SOAP version from a request's content type.
func DetectVersion(contentType string) Version {
	if strings.Contains(strings.ToLower(contentType), "application/soap+xml") {
		return Version12
	}
	return Version11
}

// Action extracts the operation the caller is invoking.
//
// SOAP 1.1 puts it in the SOAPAction header, quoted. SOAP 1.2 puts it in the
// content type as an `action` parameter. Reading only the header means every
// 1.2 client looks actionless.
func Action(contentType, soapActionHeader string) string {
	if action := strings.Trim(strings.TrimSpace(soapActionHeader), `"`); action != "" {
		return action
	}
	for _, part := range strings.Split(contentType, ";") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "action") {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

// BodyElement returns the local name of the first element inside the envelope's
// Body, which is how a SOAP request names its operation when SOAPAction does
// not.
//
// The body is returned alongside so a pass-through API can forward the exact
// bytes it received. Re-serialising the parsed document would change
// whitespace, prefixes and attribute order, and a signed envelope would no
// longer verify.
func BodyElement(reader io.Reader) (string, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, MaxEnvelopeBytes+1))
	if err != nil {
		return "", nil, fmt.Errorf("soap: cannot read envelope: %w", err)
	}
	if len(raw) > MaxEnvelopeBytes {
		return "", nil, fmt.Errorf("soap: envelope exceeds %d bytes", MaxEnvelopeBytes)
	}
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	inBody := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return "", raw, nil
		}
		if err != nil {
			return "", raw, fmt.Errorf("soap: invalid envelope: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !inBody {
			// Matched on local name and namespace so a Header element named
			// Body, or an unrelated document, cannot be mistaken for the
			// envelope's own Body.
			if start.Name.Local == "Body" && isEnvelopeNamespace(start.Name.Space) {
				inBody = true
			}
			continue
		}
		return start.Name.Local, raw, nil
	}
}

func isEnvelopeNamespace(space string) bool {
	return space == NamespaceSOAP11 || space == NamespaceSOAP12
}

// Fault renders a SOAP fault for the caller's version.
//
// A fault is how SOAP reports failure, and it is what a client's stack decodes
// into an exception. Answering with a bare HTTP error instead leaves the client
// reporting a transport failure rather than the reason, and the two are not
// interchangeable to anyone debugging.
//
// SOAP 1.1 faults use faultcode/faultstring and HTTP 500. SOAP 1.2 restructured
// them into Code/Value and Reason/Text, so a 1.1-shaped body would not decode.
func Fault(version Version, code, message string) (string, string, int) {
	escaped := escapeXML(message)
	if version == Version12 {
		body := `<?xml version="1.0" encoding="utf-8"?>` +
			`<soap:Envelope xmlns:soap="` + NamespaceSOAP12 + `"><soap:Body><soap:Fault>` +
			`<soap:Code><soap:Value>soap:` + code + `</soap:Value></soap:Code>` +
			`<soap:Reason><soap:Text xml:lang="en">` + escaped + `</soap:Text></soap:Reason>` +
			`</soap:Fault></soap:Body></soap:Envelope>`
		return body, "application/soap+xml; charset=utf-8", 500
	}
	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:soap="` + NamespaceSOAP11 + `"><soap:Body><soap:Fault>` +
		`<faultcode>soap:` + code + `</faultcode><faultstring>` + escaped + `</faultstring>` +
		`</soap:Fault></soap:Body></soap:Envelope>`
	return body, "text/xml; charset=utf-8", 500
}

// escapeXML escapes text for an XML character-data position. A fault message
// carries a caller-supplied operation name, so an unescaped `<` would produce a
// document the client cannot parse, turning a clear refusal into a parse error.
func escapeXML(value string) string {
	var builder strings.Builder
	_ = xml.EscapeText(&builder, []byte(value))
	return builder.String()
}
