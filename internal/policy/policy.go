// Package policy parses APIM policy XML into executable Go actions.
package policy

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrUnsupported is returned when execution reaches an unsupported policy.
var ErrUnsupported = errors.New("unsupported policy")

// ActionKind identifies a compiled policy operation.
type ActionKind int

const (
	ActionSetHeader ActionKind = iota
	ActionSetBackend
	ActionRewriteURI
	ActionForward
	ActionReturnResponse
	ActionUnsupported
)

// Action is a compiled policy node.
type Action struct {
	Kind       ActionKind
	Name       string
	Value      string
	BackendID  string
	Action     string
	StatusCode int
	Reason     string
	Body       string
	Headers    []Header
	Source     string
}

// Header is a set-header result.
type Header struct {
	Name   string
	Value  string
	Action string
}

// Plan contains the four APIM policy sections.
type Plan struct {
	Inbound  []Action
	Backend  []Action
	Outbound []Action
	OnError  []Action
}

// State is mutable request state exposed to policy actions.
type State struct {
	Request    *http.Request
	Response   *http.Response
	BackendURL string
	BackendID  string
	Path       string
	Returned   bool
	StatusCode int
	Reason     string
	Body       string
	Headers    http.Header
}

type node struct {
	Name     string
	Attrs    map[string]string
	Text     string
	Children []node
}

func (n *node) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	n.Name = start.Name.Local
	n.Attrs = map[string]string{}
	for _, attr := range start.Attr {
		n.Attrs[attr.Name.Local] = attr.Value
	}
	for {
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			var child node
			if err := d.DecodeElement(&child, &value); err != nil {
				return err
			}
			n.Children = append(n.Children, child)
		case xml.CharData:
			n.Text += string(value)
		case xml.EndElement:
			if value.Name == start.Name {
				return nil
			}
		}
	}
}

// Compile validates and compiles an APIM XML policy document.
func Compile(value string, strict bool) (Plan, error) {
	var root node
	if err := xml.Unmarshal([]byte(value), &root); err != nil {
		return Plan{}, fmt.Errorf("invalid policy XML: %w", err)
	}
	if root.Name != "policies" {
		return Plan{}, fmt.Errorf("policy root must be <policies>")
	}
	var plan Plan
	seen := map[string]bool{}
	for _, section := range root.Children {
		if seen[section.Name] {
			return Plan{}, fmt.Errorf("duplicate <%s> section", section.Name)
		}
		seen[section.Name] = true
		actions, err := compileNodes(section.Children, strict)
		if err != nil {
			return Plan{}, fmt.Errorf("%s: %w", section.Name, err)
		}
		switch section.Name {
		case "inbound":
			plan.Inbound = actions
		case "backend":
			plan.Backend = actions
		case "outbound":
			plan.Outbound = actions
		case "on-error":
			plan.OnError = actions
		default:
			return Plan{}, fmt.Errorf("unknown policy section <%s>", section.Name)
		}
	}
	return plan, nil
}

func compileNodes(nodes []node, strict bool) ([]Action, error) {
	var actions []Action
	for _, item := range nodes {
		action, include, err := compileNode(item)
		if err != nil {
			return nil, err
		}
		if !include {
			continue
		}
		if strict && action.Kind == ActionUnsupported {
			return nil, fmt.Errorf("%w: <%s>", ErrUnsupported, action.Source)
		}
		actions = append(actions, action)
	}
	return actions, nil
}

func compileNode(item node) (Action, bool, error) {
	switch item.Name {
	case "base":
		return Action{}, false, nil
	case "set-header":
		value := childText(item, "value")
		if expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetHeader, Name: item.Attrs["name"], Value: value, Action: item.Attrs["exists-action"]}, true, nil
	case "set-backend-service":
		value, backendID := item.Attrs["base-url"], item.Attrs["backend-id"]
		if (value == "") == (backendID == "") || expression(value) || expression(backendID) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetBackend, Value: value, BackendID: backendID}, true, nil
	case "rewrite-uri":
		value := item.Attrs["template"]
		if value == "" || expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionRewriteURI, Value: value}, true, nil
	case "forward-request":
		return Action{Kind: ActionForward}, true, nil
	case "return-response":
		result := Action{Kind: ActionReturnResponse, StatusCode: http.StatusOK}
		for _, child := range item.Children {
			switch child.Name {
			case "set-status":
				if _, err := fmt.Sscanf(child.Attrs["code"], "%d", &result.StatusCode); err != nil {
					return Action{}, false, fmt.Errorf("invalid set-status code")
				}
				result.Reason = child.Attrs["reason"]
			case "set-header":
				value := childText(child, "value")
				if expression(value) {
					return unsupported(item.Name), true, nil
				}
				result.Headers = append(result.Headers, Header{Name: child.Attrs["name"], Value: value, Action: child.Attrs["exists-action"]})
			case "set-body":
				result.Body = strings.TrimSpace(child.Text)
				if expression(result.Body) {
					return unsupported(item.Name), true, nil
				}
			default:
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
		}
		return result, true, nil
	default:
		return unsupported(item.Name), true, nil
	}
}

func unsupported(name string) Action { return Action{Kind: ActionUnsupported, Source: name} }
func expression(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "@(") || strings.HasPrefix(value, "@{")
}
func childText(item node, name string) string {
	for _, child := range item.Children {
		if child.Name == name {
			return strings.TrimSpace(child.Text)
		}
	}
	return ""
}

// Execute applies compiled actions to state.
func Execute(actions []Action, state *State) error {
	if state.Headers == nil {
		state.Headers = make(http.Header)
	}
	for _, action := range actions {
		switch action.Kind {
		case ActionSetHeader:
			target := state.Headers
			if state.Response == nil && state.Request != nil {
				target = state.Request.Header
			}
			setHeader(target, Header{Name: action.Name, Value: action.Value, Action: action.Action})
		case ActionSetBackend:
			state.BackendURL = action.Value
			state.BackendID = action.BackendID
		case ActionRewriteURI:
			state.Path = action.Value
		case ActionForward:
			// Forwarding is performed by the gateway after the backend section.
		case ActionReturnResponse:
			state.Returned, state.StatusCode, state.Reason, state.Body = true, action.StatusCode, action.Reason, action.Body
			for _, header := range action.Headers {
				setHeader(state.Headers, header)
			}
			return nil
		case ActionUnsupported:
			return fmt.Errorf("%w: <%s>", ErrUnsupported, action.Source)
		}
	}
	return nil
}

func setHeader(headers http.Header, header Header) {
	switch header.Action {
	case "append":
		headers.Add(header.Name, header.Value)
	case "skip":
		if headers.Get(header.Name) == "" {
			headers.Set(header.Name, header.Value)
		}
	case "delete":
		headers.Del(header.Name)
	default:
		headers.Set(header.Name, header.Value)
	}
}
