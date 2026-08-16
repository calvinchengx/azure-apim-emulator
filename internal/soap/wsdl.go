// Package soap compiles WSDL service definitions for the gateway.
//
// APIM's SOAP support is pass-through: the API carries a WSDL describing the
// service it fronts, and the gateway proxies SOAP envelopes to a backend that
// implements it. The WSDL buys the same thing a GraphQL schema or a protobuf
// descriptor buys, which is the reason all three exist here: the gateway can
// refuse a call the contract does not define, so the backend never sees it and
// the caller gets one answer whichever backend is behind the API.
package soap

import (
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Envelope namespaces. The version decides how the action is carried and what a
// fault looks like, so it is read from the request rather than assumed.
const (
	NamespaceSOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
	NamespaceSOAP12 = "http://www.w3.org/2003/05/soap-envelope"
)

// Schema is a compiled WSDL.
type Schema struct {
	// WSDL is the source as imported. The ARM schema resource returns exactly
	// what was uploaded, so a caller comparing what it PUT against what it GETs
	// sees no spurious difference.
	WSDL string
	// ServiceName is the first service the document defines.
	ServiceName string
	// operations is keyed by SOAPAction, and separately by the local name of
	// the request body element. Real clients identify an operation by one or
	// the other, and a gateway that reads only SOAPAction cannot route SOAP
	// 1.2 clients that omit it.
	byAction  map[string]Operation
	byElement map[string]Operation
}

// Operation is one WSDL operation.
type Operation struct {
	Name string
	// Action is the operation's soapAction, which may legitimately be empty:
	// WS-I Basic Profile allows it, and SOAP 1.2 carries the action as a
	// content-type parameter instead.
	Action string
	// InputElement is the local name of the element the request body carries.
	InputElement string
}

// definitions mirrors the subset of WSDL 1.1 the gateway needs. Parsing the
// whole schema language is not the job: routing needs the operation names,
// their actions, and the element each one expects.
type definitions struct {
	// The tag is load-bearing, not decoration: encoding/xml refuses to unmarshal
	// a document whose root is anything else, which is what rejects a non-WSDL
	// upload before any of the fields below are read.
	XMLName         xml.Name `xml:"definitions"`
	TargetNamespace string   `xml:"targetNamespace,attr"`
	Messages        []struct {
		Name  string `xml:"name,attr"`
		Parts []struct {
			Name    string `xml:"name,attr"`
			Element string `xml:"element,attr"`
			Type    string `xml:"type,attr"`
		} `xml:"part"`
	} `xml:"message"`
	PortTypes []struct {
		Name       string `xml:"name,attr"`
		Operations []struct {
			Name  string `xml:"name,attr"`
			Input struct {
				Message string `xml:"message,attr"`
			} `xml:"input"`
		} `xml:"operation"`
	} `xml:"portType"`
	Bindings []struct {
		Name       string `xml:"name,attr"`
		Type       string `xml:"type,attr"`
		Operations []struct {
			Name      string `xml:"name,attr"`
			Operation struct {
				SOAPAction string `xml:"soapAction,attr"`
			} `xml:"operation"`
		} `xml:"operation"`
	} `xml:"binding"`
	Services []struct {
		Name  string `xml:"name,attr"`
		Ports []struct {
			Name    string `xml:"name,attr"`
			Binding string `xml:"binding,attr"`
		} `xml:"port"`
	} `xml:"service"`
}

// Parse compiles a WSDL document.
func Parse(source string) (*Schema, error) {
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("soap: WSDL document is empty")
	}
	var document definitions
	if err := xml.Unmarshal([]byte(source), &document); err != nil {
		return nil, fmt.Errorf("soap: invalid WSDL: %w", err)
	}
	if len(document.Services) == 0 {
		return nil, errors.New("soap: WSDL defines no service")
	}

	// The request element of each operation, resolved through its message.
	elements := map[string]string{}
	for _, message := range document.Messages {
		for _, part := range message.Parts {
			name := part.Element
			if name == "" {
				name = part.Type
			}
			if name == "" {
				continue
			}
			elements[message.Name] = localName(name)
			break
		}
	}
	inputs := map[string]string{}
	for _, portType := range document.PortTypes {
		for _, operation := range portType.Operations {
			inputs[operation.Name] = elements[localName(operation.Input.Message)]
		}
	}

	schema := &Schema{
		WSDL:        source,
		ServiceName: document.Services[0].Name,
		byAction:    map[string]Operation{},
		byElement:   map[string]Operation{},
	}
	for _, binding := range document.Bindings {
		for _, operation := range binding.Operations {
			entry := Operation{
				Name:         operation.Name,
				Action:       operation.Operation.SOAPAction,
				InputElement: inputs[operation.Name],
			}
			if entry.InputElement == "" {
				// A document/literal WSDL commonly names the request element
				// after the operation; falling back keeps those routable rather
				// than leaving them unaddressable.
				entry.InputElement = operation.Name
			}
			if entry.Action != "" {
				schema.byAction[entry.Action] = entry
			}
			schema.byElement[entry.InputElement] = entry
		}
	}
	if len(schema.byElement) == 0 {
		return nil, errors.New("soap: WSDL defines no binding operations")
	}
	return schema, nil
}

// localName strips a namespace prefix or a URI fragment, leaving the bare name.
func localName(value string) string {
	if index := strings.LastIndex(value, "#"); index >= 0 {
		value = value[index+1:]
	}
	if index := strings.LastIndex(value, ":"); index >= 0 {
		value = value[index+1:]
	}
	return value
}

// Lookup resolves the operation a request addresses.
//
// SOAPAction is tried first because it is the explicit signal, then the body's
// first child element. Falling back matters: SOAP 1.2 clients carry the action
// in the content type and WS-I permits an empty SOAPAction, so an
// action-only gateway would reject perfectly valid callers.
func (s *Schema) Lookup(action, bodyElement string) (Operation, bool) {
	if action != "" {
		if operation, ok := s.byAction[action]; ok {
			return operation, true
		}
	}
	if bodyElement != "" {
		if operation, ok := s.byElement[bodyElement]; ok {
			return operation, true
		}
	}
	return Operation{}, false
}

// Operations lists every operation in stable order.
func (s *Schema) Operations() []Operation {
	// byElement is keyed by input element and every operation has exactly one,
	// so its values are already distinct; the map here only puts them in a
	// stable order.
	names := make([]string, 0, len(s.byElement))
	byName := map[string]Operation{}
	for _, operation := range s.byElement {
		names = append(names, operation.Name)
		byName[operation.Name] = operation
	}
	sort.Strings(names)
	list := make([]Operation, 0, len(names))
	for _, name := range names {
		list = append(list, byName[name])
	}
	return list
}
