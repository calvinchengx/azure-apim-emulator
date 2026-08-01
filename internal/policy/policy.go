// Package policy parses APIM policy XML into executable Go actions.
package policy

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ErrUnsupported is returned when execution reaches an unsupported policy.
var ErrUnsupported = errors.New("unsupported policy")

// ActionKind identifies a compiled policy operation.
type ActionKind int

const (
	ActionSetHeader ActionKind = iota
	ActionSetQueryParameter
	ActionSetVariable
	ActionSetBody
	ActionCheckHeader
	ActionValidateJWT
	ActionIPFilter
	ActionSetMethod
	ActionCORS
	ActionSendRequest
	ActionRateLimit
	ActionCacheLookup
	ActionCacheStore
	ActionValidateStatus
	ActionValidateContent
	ActionValidateHeaders
	ActionValidateParameters
	ActionValidateClientCertificate
	ActionChoose
	ActionTrace
	ActionAuthenticationBasic
	ActionAuthenticationManagedIdentity
	ActionAuthenticationOAuth2
	ActionAuthenticationCertificate
	ActionFindReplace
	ActionSetBackend
	ActionRewriteURI
	ActionForward
	ActionReturnResponse
	ActionRetry
	ActionUnsupported
)

// Action is a compiled policy node.
type Action struct {
	Kind                    ActionKind
	Name                    string
	Value                   string
	BackendID               string
	Action                  string
	StatusCode              int
	Reason                  string
	Body                    string
	Headers                 []Header
	Variable                string
	Values                  []string
	IgnoreCase              bool
	FailedCode              int
	FilterAction            string
	Methods                 string
	AllowOrigin             string
	AllowHeaders            string
	ExposeHeaders           string
	MaxAge                  string
	AllowCreds              bool
	SendURL                 string
	SendMethod              string
	ResponseVar             string
	LimitCalls              int
	LimitPeriod             time.Duration
	CacheDuration           time.Duration
	StatusMin               int
	StatusMax               int
	ContentMax              int64
	ContentAction           string
	ContentTypes            []string
	HeaderRules             []HeaderRule
	SpecifiedHeaderAction   string
	UnspecifiedHeaderAction string
	ParameterRules          []ParameterRule
	CertificateThumbprints  []string
	Branches                []ChooseBranch
	Otherwise               []Action
	TraceSource             string
	TraceSeverity           string
	TraceMessage            string
	AuthUsername            string
	AuthPassword            string
	AuthResource            string
	AuthClientID            string
	AuthClientSecret        string
	AuthTokenEndpoint       string
	AuthCertificateID       string
	ReplaceFrom             string
	ReplaceTo               string
	Children                []Action
	RetryCount              int
	RetryInterval           time.Duration
	Condition               string
	Source                  string
}

// Header is a set-header result.
type Header struct {
	Name   string
	Value  string
	Action string
}

// HeaderRule describes an allowed value for a validated header.
type HeaderRule struct {
	Name   string
	Values []string
	Action string
}

// ParameterRule describes an allowed query parameter value.
type ParameterRule struct {
	Name   string
	Values []string
	Action string
}

// ChooseBranch is a conditional policy branch.
type ChooseBranch struct {
	Condition string
	Actions   []Action
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
	Request                 *http.Request
	Response                *http.Response
	BackendURL              string
	BackendID               string
	Path                    string
	Returned                bool
	StatusCode              int
	Reason                  string
	Body                    string
	BodySet                 bool
	Headers                 http.Header
	Variables               map[string]string
	ValidateToken           func(string) error
	SendRequest             func(*http.Request) (*http.Response, error)
	Trace                   func(string, string)
	AcquireToken            func(string) (string, error)
	AcquireOAuth2Token      func(string, string, string, string) (string, error)
	AttachClientCertificate func(*http.Request, string) error
	RateLimit               func(string, int, time.Duration) bool
	CacheGet                func(string) (int, http.Header, string, bool)
	CacheSet                func(string, int, http.Header, string, time.Duration)
	CacheKey                string
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
	return compileRoot(root, strict)
}

// ValidateFragment validates the root shape of reusable fragment XML.
func ValidateFragment(value string) error {
	var root node
	if err := xml.Unmarshal([]byte(value), &root); err != nil {
		return fmt.Errorf("invalid policy fragment XML: %w", err)
	}
	if root.Name != "fragment" {
		return fmt.Errorf("policy fragment root must be <fragment>")
	}
	return nil
}

// CompileWithFragments expands include-fragment nodes before compiling a policy.
func CompileWithFragments(value string, fragments map[string]string, strict bool) (Plan, error) {
	var root node
	if err := xml.Unmarshal([]byte(value), &root); err != nil {
		return Plan{}, fmt.Errorf("invalid policy XML: %w", err)
	}
	expanded, err := expandNodes(root.Children, fragments, map[string]bool{})
	if err != nil {
		return Plan{}, err
	}
	root.Children = expanded
	return compileRoot(root, strict)
}

func expandNodes(nodes []node, fragments map[string]string, stack map[string]bool) ([]node, error) {
	result := make([]node, 0, len(nodes))
	for _, item := range nodes {
		if item.Name == "include-fragment" {
			id := strings.ToLower(item.Attrs["fragment-id"])
			value, ok := fragments[id]
			if id == "" || !ok {
				return nil, fmt.Errorf("policy fragment %q was not found", item.Attrs["fragment-id"])
			}
			if stack[id] {
				return nil, fmt.Errorf("policy fragment cycle includes %q", item.Attrs["fragment-id"])
			}
			var fragment node
			if err := xml.Unmarshal([]byte(value), &fragment); err != nil {
				return nil, fmt.Errorf("invalid policy fragment %q: %w", item.Attrs["fragment-id"], err)
			}
			if fragment.Name != "fragment" {
				return nil, fmt.Errorf("policy fragment %q root must be <fragment>", item.Attrs["fragment-id"])
			}
			stack[id] = true
			children, err := expandNodes(fragment.Children, fragments, stack)
			delete(stack, id)
			if err != nil {
				return nil, err
			}
			result = append(result, children...)
			continue
		}
		children, err := expandNodes(item.Children, fragments, stack)
		if err != nil {
			return nil, err
		}
		item.Children = children
		result = append(result, item)
	}
	return result, nil
}

func compileRoot(root node, strict bool) (Plan, error) {
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
		action, include, err := compileNode(item, strict)
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

func compileNode(item node, strict bool) (Action, bool, error) {
	switch item.Name {
	case "base":
		return Action{}, false, nil
	case "set-header":
		value := childText(item, "value")
		if expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetHeader, Name: item.Attrs["name"], Value: value, Action: item.Attrs["exists-action"]}, true, nil
	case "set-query-parameter":
		value := childText(item, "value")
		if expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetQueryParameter, Name: item.Attrs["name"], Value: value, Action: item.Attrs["exists-action"]}, true, nil
	case "set-variable":
		value := childText(item, "value")
		if expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetVariable, Variable: item.Attrs["name"], Value: value}, true, nil
	case "set-body":
		value := strings.TrimSpace(item.Text)
		if value == "" {
			value = childText(item, "value")
		}
		if expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetBody, Body: value}, true, nil
	case "check-header":
		values := make([]string, 0, len(item.Children))
		for _, child := range item.Children {
			if child.Name != "value" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			value := strings.TrimSpace(child.Text)
			if expression(value) {
				return unsupported(item.Name), true, nil
			}
			values = append(values, value)
		}
		code := http.StatusUnauthorized
		if value := item.Attrs["failed-check-httpcode"]; value != "" {
			if _, err := fmt.Sscanf(value, "%d", &code); err != nil {
				return Action{}, false, fmt.Errorf("invalid check-header status")
			}
		}
		return Action{Kind: ActionCheckHeader, Name: item.Attrs["name"], Values: values, Value: item.Attrs["failed-check-error-message"], StatusCode: code, IgnoreCase: strings.EqualFold(item.Attrs["ignore-case"], "true")}, true, nil
	case "validate-jwt":
		code := http.StatusUnauthorized
		if value := item.Attrs["failed-validation-httpcode"]; value != "" {
			if _, err := fmt.Sscanf(value, "%d", &code); err != nil {
				return Action{}, false, fmt.Errorf("invalid validate-jwt status")
			}
		}
		return Action{Kind: ActionValidateJWT, Value: item.Attrs["failed-validation-error-message"], FailedCode: code}, true, nil
	case "ip-filter":
		filterAction := strings.ToLower(item.Attrs["action"])
		if filterAction != "allow" && filterAction != "forbid" {
			return Action{}, false, fmt.Errorf("invalid ip-filter action")
		}
		values := make([]string, 0, len(item.Children))
		for _, child := range item.Children {
			if child.Name != "address" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			values = append(values, strings.TrimSpace(child.Text))
		}
		return Action{Kind: ActionIPFilter, Values: values, FilterAction: filterAction, StatusCode: http.StatusForbidden, Value: item.Attrs["failed-check-error-message"]}, true, nil
	case "set-method":
		value := strings.TrimSpace(item.Attrs["id"])
		if value == "" {
			value = strings.TrimSpace(item.Text)
		}
		if value == "" || expression(value) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionSetMethod, Value: value}, true, nil
	case "cors":
		if expression(item.Attrs["allowed-origins"]) || expression(item.Attrs["allowed-methods"]) || expression(item.Attrs["allowed-headers"]) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionCORS, AllowOrigin: item.Attrs["allowed-origins"], Methods: item.Attrs["allowed-methods"], AllowHeaders: item.Attrs["allowed-headers"], ExposeHeaders: item.Attrs["expose-headers"], MaxAge: item.Attrs["max-age"], AllowCreds: strings.EqualFold(item.Attrs["allow-credentials"], "true")}, true, nil
	case "send-request":
		action := Action{Kind: ActionSendRequest, SendMethod: http.MethodGet, ResponseVar: item.Attrs["response-variable-name"]}
		for _, child := range item.Children {
			switch child.Name {
			case "set-url":
				action.SendURL = strings.TrimSpace(child.Text)
			case "set-method":
				action.SendMethod = strings.ToUpper(strings.TrimSpace(child.Text))
			case "set-header":
				value := childText(child, "value")
				if expression(value) {
					return unsupported(item.Name), true, nil
				}
				action.Headers = append(action.Headers, Header{Name: child.Attrs["name"], Value: value, Action: child.Attrs["exists-action"]})
			case "set-body":
				action.Body = strings.TrimSpace(child.Text)
				if action.Body == "" {
					action.Body = childText(child, "value")
				}
				if expression(action.Body) {
					return unsupported(item.Name), true, nil
				}
			default:
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
		}
		if action.SendURL == "" || expression(action.SendURL) || action.SendMethod == "" {
			return unsupported(item.Name), true, nil
		}
		return action, true, nil
	case "rate-limit-by-key", "quota-by-key":
		calls, period := 0, time.Duration(0)
		if value := item.Attrs["calls"]; value != "" {
			if _, err := fmt.Sscanf(value, "%d", &calls); err != nil || calls <= 0 {
				return Action{}, false, fmt.Errorf("invalid %s calls", item.Name)
			}
		}
		if value := item.Attrs["renewal-period"]; value != "" {
			seconds, err := time.ParseDuration(value + "s")
			if err != nil || seconds <= 0 {
				return Action{}, false, fmt.Errorf("invalid %s renewal period", item.Name)
			}
			period = seconds
		}
		if calls == 0 || period == 0 || expression(item.Attrs["counter-key"]) {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionRateLimit, Value: item.Attrs["counter-key"], LimitCalls: calls, LimitPeriod: period, StatusCode: http.StatusTooManyRequests, Body: item.Attrs["retry-after-header-name"]}, true, nil
	case "cache-lookup":
		return Action{Kind: ActionCacheLookup}, true, nil
	case "cache-store":
		duration := time.Duration(0)
		if value := item.Attrs["duration"]; value != "" {
			seconds, err := time.ParseDuration(value + "s")
			if err != nil || seconds <= 0 {
				return Action{}, false, fmt.Errorf("invalid cache-store duration")
			}
			duration = seconds
		}
		if duration == 0 {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionCacheStore, CacheDuration: duration}, true, nil
	case "validate-status-code":
		min, max := 200, 299
		for _, child := range item.Children {
			if child.Name != "status-code-range" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			if value := child.Attrs["min"]; value != "" {
				if _, err := fmt.Sscanf(value, "%d", &min); err != nil {
					return Action{}, false, fmt.Errorf("invalid validate-status-code minimum")
				}
			}
			if value := child.Attrs["max"]; value != "" {
				if _, err := fmt.Sscanf(value, "%d", &max); err != nil {
					return Action{}, false, fmt.Errorf("invalid validate-status-code maximum")
				}
			}
		}
		if min < 100 || max > 599 || min > max {
			return Action{}, false, fmt.Errorf("invalid validate-status-code range")
		}
		return Action{Kind: ActionValidateStatus, StatusMin: min, StatusMax: max, Action: strings.ToLower(item.Attrs["unspecified-code-action"]), FailedCode: http.StatusBadGateway, Value: item.Attrs["errors-variable-name"]}, true, nil
	case "validate-content":
		maxSize := int64(0)
		if value := item.Attrs["max-size"]; value != "" {
			if _, err := fmt.Sscanf(value, "%d", &maxSize); err != nil || maxSize < 0 {
				return Action{}, false, fmt.Errorf("invalid validate-content max-size")
			}
		}
		sizeAction := strings.ToLower(item.Attrs["size-exceeded-action"])
		if sizeAction == "" {
			sizeAction = "prevent"
		}
		if sizeAction != "prevent" && sizeAction != "ignore" {
			return Action{}, false, fmt.Errorf("invalid validate-content size action")
		}
		contentTypes := []string{}
		for _, child := range item.Children {
			if child.Name != "content" || strings.TrimSpace(child.Attrs["type"]) == "" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			actionType := strings.ToLower(child.Attrs["action"])
			if actionType != "" && actionType != "prevent" && actionType != "ignore" {
				return Action{}, false, fmt.Errorf("invalid validate-content content action")
			}
			contentTypes = append(contentTypes, strings.ToLower(strings.TrimSpace(child.Attrs["type"])))
		}
		return Action{Kind: ActionValidateContent, ContentMax: maxSize, ContentAction: sizeAction, ContentTypes: contentTypes, FailedCode: http.StatusBadRequest}, true, nil
	case "validate-headers":
		specified := strings.ToLower(item.Attrs["specified-header-action"])
		if specified == "" {
			specified = "prevent"
		}
		unspecified := strings.ToLower(item.Attrs["unspecified-header-action"])
		if unspecified == "" {
			unspecified = "ignore"
		}
		if (specified != "prevent" && specified != "ignore") || (unspecified != "prevent" && unspecified != "ignore") {
			return Action{}, false, fmt.Errorf("invalid validate-headers action")
		}
		rules := []HeaderRule{}
		for _, child := range item.Children {
			if child.Name != "header" || strings.TrimSpace(child.Attrs["name"]) == "" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			action := strings.ToLower(child.Attrs["action"])
			if action == "" {
				action = specified
			}
			if action != "prevent" && action != "ignore" {
				return Action{}, false, fmt.Errorf("invalid validate-headers header action")
			}
			values := []string{}
			for _, value := range child.Children {
				if value.Name != "value" {
					return unsupported(item.Name + "/header/" + value.Name), true, nil
				}
				values = append(values, strings.TrimSpace(value.Text))
			}
			rules = append(rules, HeaderRule{Name: strings.ToLower(strings.TrimSpace(child.Attrs["name"])), Values: values, Action: action})
		}
		return Action{Kind: ActionValidateHeaders, HeaderRules: rules, SpecifiedHeaderAction: specified, UnspecifiedHeaderAction: unspecified, FailedCode: http.StatusBadRequest}, true, nil
	case "validate-parameters":
		specified := strings.ToLower(item.Attrs["specified-parameter-action"])
		if specified == "" {
			specified = "prevent"
		}
		unspecified := strings.ToLower(item.Attrs["unspecified-parameter-action"])
		if unspecified == "" {
			unspecified = "ignore"
		}
		if (specified != "prevent" && specified != "ignore") || (unspecified != "prevent" && unspecified != "ignore") {
			return Action{}, false, fmt.Errorf("invalid validate-parameters action")
		}
		rules := []ParameterRule{}
		for _, child := range item.Children {
			if child.Name != "parameter" || strings.TrimSpace(child.Attrs["name"]) == "" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			action := strings.ToLower(child.Attrs["action"])
			if action == "" {
				action = specified
			}
			if action != "prevent" && action != "ignore" {
				return Action{}, false, fmt.Errorf("invalid validate-parameters parameter action")
			}
			values := []string{}
			for _, value := range child.Children {
				if value.Name != "value" {
					return unsupported(item.Name + "/parameter/" + value.Name), true, nil
				}
				values = append(values, strings.TrimSpace(value.Text))
			}
			rules = append(rules, ParameterRule{Name: strings.TrimSpace(child.Attrs["name"]), Values: values, Action: action})
		}
		return Action{Kind: ActionValidateParameters, ParameterRules: rules, SpecifiedHeaderAction: specified, UnspecifiedHeaderAction: unspecified, FailedCode: http.StatusBadRequest}, true, nil
	case "validate-client-certificate":
		thumbprints := []string{}
		for _, child := range item.Children {
			if child.Name != "identities" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			for _, identity := range child.Children {
				if identity.Name != "identity" || strings.TrimSpace(identity.Attrs["thumbprint"]) == "" {
					return unsupported(item.Name + "/identities/" + identity.Name), true, nil
				}
				thumbprints = append(thumbprints, strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(identity.Attrs["thumbprint"]), ":", "")))
			}
		}
		return Action{Kind: ActionValidateClientCertificate, CertificateThumbprints: thumbprints, FailedCode: http.StatusForbidden}, true, nil
	case "choose":
		result := Action{Kind: ActionChoose}
		otherwiseSeen := false
		for _, child := range item.Children {
			switch child.Name {
			case "when":
				condition := strings.TrimSpace(child.Attrs["condition"])
				if condition == "" {
					return Action{}, false, fmt.Errorf("choose when requires a condition")
				}
				actions, err := compileNodes(child.Children, strict)
				if err != nil {
					return Action{}, false, err
				}
				result.Branches = append(result.Branches, ChooseBranch{Condition: condition, Actions: actions})
			case "otherwise":
				if otherwiseSeen {
					return Action{}, false, fmt.Errorf("choose has multiple otherwise branches")
				}
				otherwiseSeen = true
				actions, err := compileNodes(child.Children, strict)
				if err != nil {
					return Action{}, false, err
				}
				result.Otherwise = actions
			default:
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
		}
		if len(result.Branches) == 0 {
			return Action{}, false, fmt.Errorf("choose requires at least one when branch")
		}
		return result, true, nil
	case "trace":
		message := ""
		for _, child := range item.Children {
			if child.Name != "message" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			message = strings.TrimSpace(child.Text)
		}
		return Action{Kind: ActionTrace, TraceSource: item.Attrs["source"], TraceSeverity: item.Attrs["severity"], TraceMessage: message}, true, nil
	case "authentication-basic":
		username, password := item.Attrs["username"], item.Attrs["password"]
		if username == "" || password == "" || expression(username) || expression(password) {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionAuthenticationBasic, AuthUsername: username, AuthPassword: password}, true, nil
	case "authentication-managed-identity":
		resource := item.Attrs["resource"]
		if resource == "" || expression(resource) {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionAuthenticationManagedIdentity, AuthResource: resource}, true, nil
	case "authentication-oauth2":
		clientID, clientSecret, endpoint := item.Attrs["client-id"], item.Attrs["client-secret"], item.Attrs["token-endpoint"]
		if clientID == "" || clientSecret == "" || endpoint == "" || expression(clientID) || expression(clientSecret) || expression(endpoint) {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionAuthenticationOAuth2, AuthClientID: clientID, AuthClientSecret: clientSecret, AuthTokenEndpoint: endpoint, AuthResource: item.Attrs["resource"]}, true, nil
	case "authentication-certificate":
		certificateID := item.Attrs["certificate-id"]
		if certificateID == "" || expression(certificateID) {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionAuthenticationCertificate, AuthCertificateID: certificateID}, true, nil
	case "find-and-replace":
		from, to := item.Attrs["from"], item.Attrs["to"]
		if from == "" || expression(from) || expression(to) {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionFindReplace, ReplaceFrom: from, ReplaceTo: to}, true, nil
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
	case "retry":
		count := 3
		if value := item.Attrs["count"]; value != "" {
			if _, err := fmt.Sscanf(value, "%d", &count); err != nil || count < 0 {
				return Action{}, false, fmt.Errorf("invalid retry count")
			}
		}
		interval := time.Duration(0)
		if value := item.Attrs["interval"]; value != "" {
			seconds, err := time.ParseDuration(value + "s")
			if err != nil || seconds < 0 {
				return Action{}, false, fmt.Errorf("invalid retry interval")
			}
			interval = seconds
		}
		children, err := compileNodes(item.Children, strict)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionRetry, Children: children, RetryCount: count, RetryInterval: interval, Condition: item.Attrs["condition"]}, true, nil
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

func ipMatches(remote, rule string) bool {
	ip := net.ParseIP(strings.TrimSpace(remote))
	if ip == nil {
		return false
	}
	if strings.Contains(rule, "/") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(rule))
		return err == nil && network.Contains(ip)
	}
	return ip.Equal(net.ParseIP(strings.TrimSpace(rule)))
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
		case ActionSetQueryParameter:
			if state.Request == nil {
				return fmt.Errorf("set-query-parameter requires a request")
			}
			query := state.Request.URL.Query()
			switch action.Action {
			case "delete":
				query.Del(action.Name)
			case "skip":
				if !query.Has(action.Name) {
					query.Set(action.Name, action.Value)
				}
			default:
				query.Set(action.Name, action.Value)
			}
			state.Request.URL.RawQuery = query.Encode()
		case ActionSetVariable:
			if state.Variables == nil {
				state.Variables = map[string]string{}
			}
			state.Variables[action.Variable] = action.Value
		case ActionSetBody:
			if state.Response == nil && state.Request != nil {
				state.Request.Body = io.NopCloser(strings.NewReader(action.Body))
				state.Request.ContentLength = int64(len(action.Body))
				state.Request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(action.Body)), nil
				}
			} else {
				state.Body, state.BodySet = action.Body, true
			}
		case ActionCheckHeader:
			if state.Request == nil {
				return fmt.Errorf("check-header requires a request")
			}
			actual := state.Request.Header.Values(action.Name)
			matched := false
			for _, candidate := range actual {
				for _, allowed := range action.Values {
					if (action.IgnoreCase && strings.EqualFold(candidate, allowed)) || (!action.IgnoreCase && candidate == allowed) {
						matched = true
					}
				}
			}
			if !matched {
				state.Returned, state.StatusCode, state.Body = true, action.StatusCode, action.Value
				return nil
			}
		case ActionValidateJWT:
			if state.Request == nil || state.ValidateToken == nil {
				return fmt.Errorf("validate-jwt requires a configured token validator")
			}
			header := state.Request.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") || state.ValidateToken(strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))) != nil {
				state.Returned, state.StatusCode, state.Body = true, action.FailedCode, action.Value
				return nil
			}
		case ActionIPFilter:
			if state.Request == nil {
				return fmt.Errorf("ip-filter requires a request")
			}
			remote := state.Request.RemoteAddr
			if host, _, err := net.SplitHostPort(remote); err == nil {
				remote = host
			}
			matched := false
			for _, value := range action.Values {
				if ipMatches(remote, value) {
					matched = true
					break
				}
			}
			failed := (action.FilterAction == "allow" && !matched) || (action.FilterAction == "forbid" && matched)
			if failed {
				state.Returned, state.StatusCode, state.Body = true, action.StatusCode, action.Value
				return nil
			}
		case ActionSetMethod:
			if state.Request == nil {
				return fmt.Errorf("set-method requires a request")
			}
			state.Request.Method = strings.ToUpper(action.Value)
		case ActionCORS:
			if state.Request == nil {
				return fmt.Errorf("cors requires a request")
			}
			origin := state.Request.Header.Get("Origin")
			if origin == "" {
				continue
			}
			state.Headers.Set("Access-Control-Allow-Origin", action.AllowOrigin)
			if action.AllowCreds {
				state.Headers.Set("Access-Control-Allow-Credentials", "true")
			}
			if action.Methods != "" {
				state.Headers.Set("Access-Control-Allow-Methods", action.Methods)
			}
			if action.AllowHeaders != "" {
				state.Headers.Set("Access-Control-Allow-Headers", action.AllowHeaders)
			}
			if action.ExposeHeaders != "" {
				state.Headers.Set("Access-Control-Expose-Headers", action.ExposeHeaders)
			}
			if action.MaxAge != "" {
				state.Headers.Set("Access-Control-Max-Age", action.MaxAge)
			}
			if state.Request.Method == http.MethodOptions {
				state.Returned, state.StatusCode = true, http.StatusNoContent
			}
		case ActionSendRequest:
			if state.SendRequest == nil {
				return fmt.Errorf("send-request requires a configured transport")
			}
			request, err := http.NewRequest(action.SendMethod, action.SendURL, strings.NewReader(action.Body))
			if err != nil {
				return err
			}
			for _, header := range action.Headers {
				setHeader(request.Header, header)
			}
			response, err := state.SendRequest(request)
			if err != nil {
				return err
			}
			if response != nil {
				if response.Body != nil {
					_ = response.Body.Close()
				}
				if action.ResponseVar != "" {
					if state.Variables == nil {
						state.Variables = map[string]string{}
					}
					state.Variables[action.ResponseVar] = fmt.Sprintf("%d", response.StatusCode)
				}
			}
		case ActionRateLimit:
			if state.RateLimit == nil {
				return fmt.Errorf("rate-limit requires a configured limiter")
			}
			key := action.Value
			if key == "" && state.Request != nil {
				key = state.Request.RemoteAddr
			}
			if state.RateLimit(key, action.LimitCalls, action.LimitPeriod) {
				state.Returned, state.StatusCode = true, action.StatusCode
				if action.Body != "" {
					state.Headers.Set(action.Body, "true")
				}
				return nil
			}
		case ActionCacheLookup:
			if state.CacheGet == nil {
				return fmt.Errorf("cache-lookup requires a configured cache")
			}
			if status, headers, body, ok := state.CacheGet(state.CacheKey); ok {
				state.Headers = headers
				state.Returned, state.StatusCode, state.Body = true, status, body
				return nil
			}
		case ActionCacheStore:
			if state.CacheSet == nil || state.Response == nil {
				return fmt.Errorf("cache-store requires a response and configured cache")
			}
			body := state.Body
			if !state.BodySet {
				value, err := io.ReadAll(state.Response.Body)
				if err != nil {
					return err
				}
				body = string(value)
				state.Response.Body = io.NopCloser(strings.NewReader(body))
			}
			state.CacheSet(state.CacheKey, state.Response.StatusCode, state.Response.Header.Clone(), body, action.CacheDuration)
		case ActionValidateStatus:
			if state.Response == nil {
				return fmt.Errorf("validate-status-code requires a response")
			}
			valid := state.Response.StatusCode >= action.StatusMin && state.Response.StatusCode <= action.StatusMax
			if !valid && action.Action != "ignore" {
				state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "response status code is outside the configured range"
				if action.Value != "" {
					if state.Variables == nil {
						state.Variables = map[string]string{}
					}
					state.Variables[action.Value] = fmt.Sprintf("%d", state.Response.StatusCode)
				}
				return nil
			}
		case ActionValidateContent:
			var headers http.Header
			var body io.ReadCloser
			if state.Response != nil {
				headers, body = state.Response.Header, state.Response.Body
			} else if state.Request != nil {
				headers, body = state.Request.Header, state.Request.Body
			} else {
				return fmt.Errorf("validate-content requires a request or response")
			}
			value, err := io.ReadAll(body)
			if err != nil {
				return err
			}
			if state.Response != nil {
				state.Response.Body = io.NopCloser(strings.NewReader(string(value)))
			} else {
				state.Request.Body = io.NopCloser(strings.NewReader(string(value)))
				state.Request.ContentLength = int64(len(value))
			}
			failed := (action.ContentMax > 0 && int64(len(value)) > action.ContentMax)
			if len(action.ContentTypes) > 0 {
				contentType := strings.ToLower(strings.Split(headers.Get("Content-Type"), ";")[0])
				matched := false
				for _, allowed := range action.ContentTypes {
					if contentType == allowed {
						matched = true
						break
					}
				}
				failed = failed || !matched
			}
			if failed && action.ContentAction != "ignore" {
				state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "content validation failed"
				return nil
			}
		case ActionValidateHeaders:
			var headers http.Header
			if state.Response != nil {
				headers = state.Response.Header
			} else if state.Request != nil {
				headers = state.Request.Header
			} else {
				return fmt.Errorf("validate-headers requires a request or response")
			}
			rules := make(map[string]HeaderRule, len(action.HeaderRules))
			for _, rule := range action.HeaderRules {
				rules[strings.ToLower(rule.Name)] = rule
			}
			for name, values := range headers {
				rule, specified := rules[strings.ToLower(name)]
				if !specified {
					if action.UnspecifiedHeaderAction == "prevent" {
						state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "header validation failed"
						return nil
					}
					continue
				}
				if rule.Action == "ignore" || len(rule.Values) == 0 {
					continue
				}
				matched := false
				for _, actual := range values {
					for _, expected := range rule.Values {
						if actual == expected {
							matched = true
						}
					}
				}
				if !matched {
					state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "header validation failed"
					return nil
				}
			}
			for _, rule := range rules {
				if len(headers.Values(rule.Name)) == 0 && rule.Action == "prevent" {
					state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "header validation failed"
					return nil
				}
			}
		case ActionValidateParameters:
			if state.Request == nil || state.Request.URL == nil {
				return fmt.Errorf("validate-parameters requires a request")
			}
			query := state.Request.URL.Query()
			rules := make(map[string]ParameterRule, len(action.ParameterRules))
			for _, rule := range action.ParameterRules {
				rules[rule.Name] = rule
			}
			for name, values := range query {
				rule, specified := rules[name]
				if !specified {
					if action.UnspecifiedHeaderAction == "prevent" {
						state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "parameter validation failed"
						return nil
					}
					continue
				}
				if rule.Action == "ignore" || len(rule.Values) == 0 {
					continue
				}
				matched := false
				for _, actual := range values {
					for _, expected := range rule.Values {
						if actual == expected {
							matched = true
						}
					}
				}
				if !matched {
					state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "parameter validation failed"
					return nil
				}
			}
			for _, rule := range rules {
				if _, present := query[rule.Name]; !present && rule.Action == "prevent" {
					state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "parameter validation failed"
					return nil
				}
			}
		case ActionValidateClientCertificate:
			if state.Request == nil || state.Request.TLS == nil || len(state.Request.TLS.PeerCertificates) == 0 {
				state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "client certificate validation failed"
				return nil
			}
			if len(action.CertificateThumbprints) > 0 {
				matched := false
				for _, certificate := range state.Request.TLS.PeerCertificates {
					fingerprint := strings.ToUpper(fmt.Sprintf("%X", sha1.Sum(certificate.Raw)))
					for _, expected := range action.CertificateThumbprints {
						if fingerprint == expected {
							matched = true
						}
					}
				}
				if !matched {
					state.Returned, state.StatusCode, state.Body = true, action.FailedCode, "client certificate validation failed"
					return nil
				}
			}
		case ActionChoose:
			selected := action.Otherwise
			for _, branch := range action.Branches {
				matched, err := evaluateCondition(branch.Condition, state)
				if err != nil {
					return err
				}
				if matched {
					selected = branch.Actions
					break
				}
			}
			if err := Execute(selected, state); err != nil {
				return err
			}
			if state.Returned {
				return nil
			}
		case ActionTrace:
			if state.Trace != nil {
				state.Trace("policy", strings.TrimSpace(action.TraceSource+" "+action.TraceSeverity+" "+action.TraceMessage))
			}
		case ActionAuthenticationBasic:
			if state.Request == nil {
				return fmt.Errorf("authentication-basic requires a request")
			}
			state.Request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(action.AuthUsername+":"+action.AuthPassword)))
		case ActionAuthenticationManagedIdentity:
			if state.Request == nil {
				return fmt.Errorf("authentication-managed-identity requires a request")
			}
			if state.AcquireToken == nil {
				return fmt.Errorf("authentication-managed-identity requires a token provider")
			}
			token, err := state.AcquireToken(action.AuthResource)
			if err != nil {
				return err
			}
			state.Request.Header.Set("Authorization", "Bearer "+token)
		case ActionAuthenticationOAuth2:
			if state.Request == nil {
				return fmt.Errorf("authentication-oauth2 requires a request")
			}
			if state.AcquireOAuth2Token == nil {
				return fmt.Errorf("authentication-oauth2 requires a token provider")
			}
			token, err := state.AcquireOAuth2Token(action.AuthClientID, action.AuthClientSecret, action.AuthTokenEndpoint, action.AuthResource)
			if err != nil {
				return err
			}
			state.Request.Header.Set("Authorization", "Bearer "+token)
		case ActionAuthenticationCertificate:
			if state.Request == nil {
				return fmt.Errorf("authentication-certificate requires a request")
			}
			if state.AttachClientCertificate == nil {
				return fmt.Errorf("authentication-certificate requires a certificate provider")
			}
			if err := state.AttachClientCertificate(state.Request, action.AuthCertificateID); err != nil {
				return err
			}
		case ActionFindReplace:
			var body io.ReadCloser
			if state.Response != nil {
				body = state.Response.Body
			} else if state.Request != nil {
				body = state.Request.Body
			} else {
				return fmt.Errorf("find-and-replace requires a request or response")
			}
			value, err := io.ReadAll(body)
			if err != nil {
				return err
			}
			replaced := strings.ReplaceAll(string(value), action.ReplaceFrom, action.ReplaceTo)
			if state.Response != nil {
				state.Response.Body = io.NopCloser(strings.NewReader(replaced))
			} else {
				state.Request.Body = io.NopCloser(strings.NewReader(replaced))
				state.Request.ContentLength = int64(len(replaced))
				state.Request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(replaced)), nil }
			}
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
		case ActionRetry:
			if err := Execute(action.Children, state); err != nil {
				return err
			}
		case ActionUnsupported:
			return fmt.Errorf("%w: <%s>", ErrUnsupported, action.Source)
		}
	}
	return nil
}

func evaluateCondition(condition string, state *State) (bool, error) {
	condition = strings.TrimSpace(condition)
	switch strings.ToLower(condition) {
	case "true", "@(true)":
		return true, nil
	case "false", "@(false)":
		return false, nil
	}
	if state.Request == nil {
		return false, fmt.Errorf("choose condition requires a request")
	}
	condition = strings.TrimSpace(strings.TrimPrefix(condition, "@("))
	condition = strings.TrimSuffix(condition, ")")
	parts := strings.SplitN(condition, "==", 2)
	if len(parts) != 2 {
		return false, fmt.Errorf("unsupported choose condition %q", condition)
	}
	left := strings.TrimSpace(parts[0])
	right := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
	switch left {
	case "context.Request.Method":
		return state.Request.Method == right, nil
	case "context.Request.Url.Path", "context.Request.URL.Path":
		return state.Request.URL.Path == right, nil
	default:
		return false, fmt.Errorf("unsupported choose condition %q", condition)
	}
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
