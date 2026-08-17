// Package policy parses APIM policy XML into executable Go actions.
package policy

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	expr "github.com/calvinchengx/azure-apim-emulator/internal/expression"
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
	ActionGetAuthorizationContext
	ActionRateLimit
	ActionLimitConcurrency
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
	ActionJSONToXML
	ActionXMLToJSON
	ActionJSONP
	ActionBase
	ActionCacheLookupValue
	ActionCacheStoreValue
	ActionCacheRemoveValue
	ActionSetBackend
	ActionRewriteURI
	ActionForward
	ActionReturnResponse
	ActionRetry
	ActionWait
	ActionSetStatus
	ActionSendOneWay
	ActionRedirectContentURLs
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
	LimitBandwidth          int64
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
	Audiences               []string
	Issuers                 []string
	ClientAppIDs            []string
	Claims                  []ClaimConstraint
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
	TransformRoot           string
	JSONPParameter          string
	ValueCacheKey           string
	ValueCacheValue         string
	ValueCacheDuration      time.Duration
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

// ClaimConstraint is a required JWT or Entra claim check.
type ClaimConstraint struct {
	Name      string
	Values    []string
	MatchAny  bool
	Separator string
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
	Request    *http.Request
	Response   *http.Response
	BackendURL string
	BackendID  string
	Path       string
	Returned   bool
	StatusCode int
	Reason     string
	Body       string
	BodySet    bool
	Headers    http.Header
	Variables  map[string]string
	// AuthorizationContexts holds credentials fetched by
	// get-authorization-context, keyed by the variable name the policy chose.
	// Separate from Variables because a credential is an object and Variables
	// is text-only.
	AuthorizationContexts map[string]expr.AuthorizationContext
	// FetchCredential resolves a stored credential to a usable token. Supplied
	// by the gateway, which owns the store and the OAuth2 client; the policy
	// package must not reach for either.
	FetchCredential         func(providerID, authorizationID string) (expr.AuthorizationContext, error)
	ValidateToken           func(string) error
	SendRequest             func(*http.Request) (*http.Response, error)
	Trace                   func(string, string)
	AcquireToken            func(string) (string, error)
	AcquireOAuth2Token      func(string, string, string, string) (string, error)
	AttachClientCertificate func(*http.Request, string) error
	ValueCacheGet           func(string) (string, bool)
	ValueCacheSet           func(string, string, time.Duration)
	ValueCacheRemove        func(string)
	RateLimit               func(string, int, time.Duration) bool
	BandwidthLimit          func(string, int64, int64, time.Duration) bool
	AcquireConcurrency      func(string, int) func()
	ConcurrencyReleases     []func()
	CacheGet                func(string) (int, http.Header, string, bool)
	CacheSet                func(string, int, http.Header, string, time.Duration)
	CacheKey                string
	LastError               error
	Api                     *expr.ApiContext
	Operation               *expr.OperationContext
	Product                 *expr.NamedContext
	Subscription            *expr.NamedContext
	User                    *expr.NamedContext
	Deployment              *expr.DeploymentContext
	GraphQL                 *expr.GraphQLContext
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
		action, _, err := compileNode(item, strict)
		if err != nil {
			return nil, err
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
		return Action{Kind: ActionBase}, true, nil
	case "set-header":
		value, err := compileValue(childText(item, "value"))
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionSetHeader, Name: item.Attrs["name"], Value: value, Action: item.Attrs["exists-action"]}, true, nil
	case "set-query-parameter":
		value, err := compileValue(childText(item, "value"))
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionSetQueryParameter, Name: item.Attrs["name"], Value: value, Action: item.Attrs["exists-action"]}, true, nil
	case "get-authorization-context":
		// Credential manager. provider-id and authorization-id name the stored
		// credential; context-variable-name is where the result lands for the
		// rest of the pipeline to read.
		variable := item.Attrs["context-variable-name"]
		if item.Attrs["provider-id"] == "" || item.Attrs["authorization-id"] == "" || variable == "" {
			return unsupported(item.Name), true, nil
		}
		ignore := strings.EqualFold(item.Attrs["ignore-error"], "true")
		return Action{
			Kind: ActionGetAuthorizationContext, Name: item.Attrs["provider-id"],
			Value: item.Attrs["authorization-id"], Variable: variable, IgnoreCase: ignore,
		}, true, nil
	case "set-variable":
		value, err := compileValue(childText(item, "value"))
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionSetVariable, Variable: item.Attrs["name"], Value: value}, true, nil
	case "set-body":
		value := strings.TrimSpace(item.Text)
		if value == "" {
			value = childText(item, "value")
		}
		value, err := compileValue(value)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionSetBody, Body: value}, true, nil
	case "check-header":
		values := make([]string, 0, len(item.Children))
		for _, child := range item.Children {
			if child.Name != "value" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
			value, err := compileValue(strings.TrimSpace(child.Text))
			if err != nil {
				return Action{}, false, err
			}
			values = append(values, value)
		}
		code := http.StatusUnauthorized
		if value := item.Attrs["failed-check-httpcode"]; value != "" {
			if _, err := fmt.Sscanf(value, "%d", &code); err != nil {
				return Action{}, false, fmt.Errorf("invalid check-header status")
			}
		}
		name, err := compileValue(item.Attrs["name"])
		if err != nil {
			return Action{}, false, err
		}
		message, err := compileValue(item.Attrs["failed-check-error-message"])
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionCheckHeader, Name: name, Values: values, Value: message, StatusCode: code, IgnoreCase: strings.EqualFold(item.Attrs["ignore-case"], "true")}, true, nil
	case "validate-jwt":
		return compileValidateJWT(item)
	case "validate-azure-ad-token":
		return compileValidateAzureADToken(item)
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
		if value == "" {
			return unsupported(item.Name), true, nil
		}
		value, err := compileValue(value)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionSetMethod, Value: value}, true, nil
	case "cors":
		allowOrigin, err := compileValue(item.Attrs["allowed-origins"])
		if err != nil {
			return Action{}, false, err
		}
		methods, err := compileValue(item.Attrs["allowed-methods"])
		if err != nil {
			return Action{}, false, err
		}
		allowHeaders, err := compileValue(item.Attrs["allowed-headers"])
		if err != nil {
			return Action{}, false, err
		}
		exposeHeaders, err := compileValue(item.Attrs["expose-headers"])
		if err != nil {
			return Action{}, false, err
		}
		maxAge, err := compileValue(item.Attrs["max-age"])
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionCORS, AllowOrigin: allowOrigin, Methods: methods, AllowHeaders: allowHeaders, ExposeHeaders: exposeHeaders, MaxAge: maxAge, AllowCreds: strings.EqualFold(item.Attrs["allow-credentials"], "true")}, true, nil
	case "send-request", "send-one-way-request":
		return compileSendRequest(item)
	case "rate-limit-by-key", "quota-by-key", "rate-limit", "quota":
		return compileLimit(item)
	case "limit-concurrency":
		count, err := strconv.Atoi(item.Attrs["max-count"])
		if err != nil || count <= 0 {
			return unsupported(item.Name), true, nil
		}
		for _, child := range item.Children {
			if child.Name != "wait" {
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
		}
		key, err := compileValue(item.Attrs["key"])
		if err != nil {
			return Action{}, false, err
		}
		children, err := compileNodes(item.Children, strict)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionLimitConcurrency, Value: key, LimitCalls: count, StatusCode: http.StatusTooManyRequests, Body: "concurrency limit exceeded", Children: children}, true, nil
	case "wait":
		return compileWait(item, strict)
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
		if username == "" || password == "" {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		username, err := compileValue(username)
		if err != nil {
			return Action{}, false, err
		}
		password, err = compileValue(password)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionAuthenticationBasic, AuthUsername: username, AuthPassword: password}, true, nil
	case "authentication-managed-identity":
		resource := item.Attrs["resource"]
		if resource == "" {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		resource, err := compileValue(resource)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionAuthenticationManagedIdentity, AuthResource: resource}, true, nil
	case "authentication-oauth2":
		clientID, clientSecret, endpoint := item.Attrs["client-id"], item.Attrs["client-secret"], item.Attrs["token-endpoint"]
		if clientID == "" || clientSecret == "" || endpoint == "" {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		clientID, err := compileValue(clientID)
		if err != nil {
			return Action{}, false, err
		}
		clientSecret, err = compileValue(clientSecret)
		if err != nil {
			return Action{}, false, err
		}
		endpoint, err = compileValue(endpoint)
		if err != nil {
			return Action{}, false, err
		}
		resource, err := compileValue(item.Attrs["resource"])
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionAuthenticationOAuth2, AuthClientID: clientID, AuthClientSecret: clientSecret, AuthTokenEndpoint: endpoint, AuthResource: resource}, true, nil
	case "authentication-certificate":
		certificateID := item.Attrs["certificate-id"]
		if certificateID == "" {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		certificateID, err := compileValue(certificateID)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionAuthenticationCertificate, AuthCertificateID: certificateID}, true, nil
	case "find-and-replace":
		from, err := compileValue(item.Attrs["from"])
		if err != nil {
			return Action{}, false, err
		}
		to, err := compileValue(item.Attrs["to"])
		if err != nil {
			return Action{}, false, err
		}
		if from == "" {
			return unsupported(item.Name), true, nil
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionFindReplace, ReplaceFrom: from, ReplaceTo: to}, true, nil
	case "json-to-xml":
		root := item.Attrs["root-element-name"]
		if root == "" {
			root = "root"
		}
		if len(item.Children) > 0 {
			return unsupported(item.Name), true, nil
		}
		root, err := compileValue(root)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionJSONToXML, TransformRoot: root}, true, nil
	case "xml-to-json":
		if len(item.Children) > 0 {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionXMLToJSON}, true, nil
	case "jsonp":
		parameter := item.Attrs["callback-parameter-name"]
		if parameter == "" || len(item.Children) > 0 {
			return unsupported(item.Name), true, nil
		}
		parameter, err := compileValue(parameter)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionJSONP, JSONPParameter: parameter}, true, nil
	case "cache-lookup-value":
		key, err := compileValue(item.Attrs["key"])
		if err != nil {
			return Action{}, false, err
		}
		variable, err := compileValue(item.Attrs["variable-name"])
		if err != nil {
			return Action{}, false, err
		}
		if key == "" || variable == "" || len(item.Children) > 0 {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionCacheLookupValue, ValueCacheKey: key, Variable: variable}, true, nil
	case "cache-store-value":
		key, err := compileValue(item.Attrs["key"])
		if err != nil {
			return Action{}, false, err
		}
		value, err := compileValue(item.Attrs["value"])
		if err != nil {
			return Action{}, false, err
		}
		if key == "" || len(item.Children) > 0 {
			return unsupported(item.Name), true, nil
		}
		duration := 300 * time.Second
		if raw := item.Attrs["duration"]; raw != "" {
			seconds, err := strconv.Atoi(raw)
			if err != nil || seconds <= 0 {
				return Action{}, false, fmt.Errorf("invalid cache-store-value duration")
			}
			duration = time.Duration(seconds) * time.Second
		}
		return Action{Kind: ActionCacheStoreValue, ValueCacheKey: key, ValueCacheValue: value, ValueCacheDuration: duration}, true, nil
	case "cache-remove-value":
		key, err := compileValue(item.Attrs["key"])
		if err != nil {
			return Action{}, false, err
		}
		if key == "" || len(item.Children) > 0 {
			return unsupported(item.Name), true, nil
		}
		return Action{Kind: ActionCacheRemoveValue, ValueCacheKey: key}, true, nil
	case "set-backend-service":
		value, backendID := item.Attrs["base-url"], item.Attrs["backend-id"]
		if (value == "") == (backendID == "") {
			return unsupported(item.Name), true, nil
		}
		value, err := compileValue(value)
		if err != nil {
			return Action{}, false, err
		}
		backendID, err = compileValue(backendID)
		if err != nil {
			return Action{}, false, err
		}
		return Action{Kind: ActionSetBackend, Value: value, BackendID: backendID}, true, nil
	case "rewrite-uri":
		value := item.Attrs["template"]
		if value == "" {
			return unsupported(item.Name), true, nil
		}
		value, err := compileValue(value)
		if err != nil {
			return Action{}, false, err
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
				value, err := compileValue(childText(child, "value"))
				if err != nil {
					return Action{}, false, err
				}
				result.Headers = append(result.Headers, Header{Name: child.Attrs["name"], Value: value, Action: child.Attrs["exists-action"]})
			case "set-body":
				body, err := compileValue(strings.TrimSpace(child.Text))
				if err != nil {
					return Action{}, false, err
				}
				result.Body = body
			default:
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
		}
		return result, true, nil
	case "set-status":
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		code, err := compileValue(item.Attrs["code"])
		if err != nil {
			return Action{}, false, err
		}
		reason, err := compileValue(item.Attrs["reason"])
		if err != nil {
			return Action{}, false, err
		}
		action := Action{Kind: ActionSetStatus, Reason: reason}
		if expression(code) {
			action.Value = code
			return action, true, nil
		}
		parsed := 0
		if _, err := fmt.Sscanf(code, "%d", &parsed); err != nil || parsed < 100 || parsed > 599 {
			return Action{}, false, fmt.Errorf("invalid set-status code")
		}
		action.StatusCode = parsed
		return action, true, nil
	case "cross-domain":
		var body strings.Builder
		for _, child := range item.Children {
			writeNodeXML(&body, child)
		}
		return Action{Kind: ActionReturnResponse, StatusCode: http.StatusOK, Body: body.String(), Headers: []Header{{Name: "Content-Type", Value: "text/x-cross-domain-policy", Action: "override"}}}, true, nil
	case "redirect-content-urls":
		if len(item.Children) > 0 {
			return unsupported(item.Name + "/" + item.Children[0].Name), true, nil
		}
		return Action{Kind: ActionRedirectContentURLs}, true, nil
	case "mock-response":
		body := ""
		for _, child := range item.Children {
			switch child.Name {
			case "example":
				value, err := compileValue(strings.TrimSpace(child.Text))
				if err != nil {
					return Action{}, false, err
				}
				body = value
			case "schema":
				return unsupported(item.Name + "/schema"), true, nil
			default:
				return unsupported(item.Name + "/" + child.Name), true, nil
			}
		}
		codeValue, err := compileValue(item.Attrs["status-code"])
		if err != nil {
			return Action{}, false, err
		}
		contentType, err := compileValue(item.Attrs["content-type"])
		if err != nil {
			return Action{}, false, err
		}
		result := Action{Kind: ActionReturnResponse, StatusCode: http.StatusOK, Body: body}
		if expression(codeValue) {
			result.Value = codeValue
			result.StatusCode = 0
		} else if codeValue != "" {
			code := 0
			if _, err := fmt.Sscanf(codeValue, "%d", &code); err != nil || code < 100 || code > 599 {
				return Action{}, false, fmt.Errorf("invalid mock-response status-code")
			}
			result.StatusCode = code
		}
		if contentType != "" {
			result.Headers = []Header{{Name: "Content-Type", Value: contentType, Action: "override"}}
		}
		return result, true, nil
	default:
		return unsupported(item.Name), true, nil
	}
}

func compileLimit(item node) (Action, bool, error) {
	calls, period, bandwidth, err := parseLimitBudget(item)
	if err != nil {
		return Action{}, false, err
	}
	key := item.Attrs["counter-key"]
	if key == "" && (item.Name == "rate-limit" || item.Name == "quota") {
		key = item.Name
	}
	key, err = compileValue(key)
	if err != nil {
		return Action{}, false, err
	}
	if (calls == 0 && bandwidth == 0) || period == 0 || key == "" {
		return unsupported(item.Name), true, nil
	}
	children := make([]Action, 0, len(item.Children))
	for _, child := range item.Children {
		if child.Name != "api" && child.Name != "operation" {
			return unsupported(item.Name + "/" + child.Name), true, nil
		}
		nested, err := compileNestedLimit(item.Name, period, child)
		if err != nil {
			return Action{}, false, err
		}
		if nested.Kind == ActionUnsupported {
			return nested, true, nil
		}
		children = append(children, nested)
	}
	status := http.StatusTooManyRequests
	if item.Name == "quota" || item.Name == "quota-by-key" {
		status = http.StatusForbidden
	}
	retryAfter := item.Attrs["retry-after-header-name"]
	if retryAfter == "" && (item.Name == "rate-limit" || item.Name == "quota") {
		retryAfter = "Retry-After"
	}
	return Action{Kind: ActionRateLimit, Value: key, LimitCalls: calls, LimitBandwidth: bandwidth, LimitPeriod: period, StatusCode: status, Body: retryAfter, Children: children}, true, nil
}

func compileNestedLimit(parent string, parentPeriod time.Duration, item node) (Action, error) {
	name := strings.TrimSpace(item.Attrs["name"])
	if name == "" {
		return unsupported(parent + "/" + item.Name), nil
	}
	calls, period, bandwidth, err := parseLimitBudget(item)
	if err != nil {
		return Action{}, err
	}
	if period == 0 {
		period = parentPeriod
	}
	if calls == 0 && bandwidth == 0 {
		return unsupported(parent + "/" + item.Name), nil
	}
	children := make([]Action, 0, len(item.Children))
	for _, child := range item.Children {
		if item.Name != "api" || child.Name != "operation" {
			return unsupported(parent + "/" + item.Name + "/" + child.Name), nil
		}
		nested, err := compileNestedLimit(parent+"/"+item.Name, period, child)
		if err != nil {
			return Action{}, err
		}
		if nested.Kind == ActionUnsupported {
			return nested, nil
		}
		children = append(children, nested)
	}
	status := http.StatusTooManyRequests
	if strings.HasPrefix(parent, "quota") {
		status = http.StatusForbidden
	}
	return Action{Kind: ActionRateLimit, Value: parent + "/" + item.Name + "/" + name, LimitCalls: calls, LimitBandwidth: bandwidth, LimitPeriod: period, StatusCode: status, Children: children}, nil
}

func parseLimitBudget(item node) (int, time.Duration, int64, error) {
	calls, period, bandwidth := 0, time.Duration(0), int64(0)
	if value := item.Attrs["calls"]; value != "" {
		if _, err := fmt.Sscanf(value, "%d", &calls); err != nil || calls <= 0 {
			return 0, 0, 0, fmt.Errorf("invalid %s calls", item.Name)
		}
	}
	if value := item.Attrs["renewal-period"]; value != "" {
		seconds, err := time.ParseDuration(value + "s")
		if err != nil || seconds <= 0 {
			return 0, 0, 0, fmt.Errorf("invalid %s renewal period", item.Name)
		}
		period = seconds
	}
	if value := item.Attrs["bandwidth"]; value != "" {
		if _, err := fmt.Sscanf(value, "%d", &bandwidth); err != nil || bandwidth <= 0 {
			return 0, 0, 0, fmt.Errorf("invalid %s bandwidth", item.Name)
		}
	}
	if item.Name == "rate-limit" && period > 300*time.Second {
		return 0, 0, 0, fmt.Errorf("invalid rate-limit renewal period")
	}
	return calls, period, bandwidth, nil
}

func compileWait(item node, strict bool) (Action, bool, error) {
	mode := strings.ToLower(strings.TrimSpace(item.Attrs["for"]))
	if mode == "" {
		mode = "all"
	}
	if mode != "all" && mode != "any" && mode != "self" {
		return unsupported(item.Name), true, nil
	}
	for _, child := range item.Children {
		switch child.Name {
		case "send-request", "cache-lookup-value", "choose":
		default:
			return unsupported(item.Name + "/" + child.Name), true, nil
		}
	}
	children, err := compileNodes(item.Children, strict)
	if err != nil {
		return Action{}, false, err
	}
	return Action{Kind: ActionWait, Action: mode, Children: children}, true, nil
}

func compileValidateJWT(item node) (Action, bool, error) {
	code := http.StatusUnauthorized
	if value := item.Attrs["failed-validation-httpcode"]; value != "" {
		if _, err := fmt.Sscanf(value, "%d", &code); err != nil {
			return Action{}, false, fmt.Errorf("invalid validate-jwt status")
		}
	}
	constraints, source := compileTokenConstraints(item)
	if source != "" {
		return unsupported(source), true, nil
	}
	return Action{Kind: ActionValidateJWT, Value: item.Attrs["failed-validation-error-message"], FailedCode: code, Audiences: constraints.Audiences, Issuers: constraints.Issuers, Claims: constraints.Claims}, true, nil
}

func compileValidateAzureADToken(item node) (Action, bool, error) {
	tenantID, err := compileValue(item.Attrs["tenant-id"])
	if err != nil {
		return Action{}, false, err
	}
	headerName, err := compileValue(item.Attrs["header-name"])
	if err != nil {
		return Action{}, false, err
	}
	queryName, err := compileValue(item.Attrs["query-parameter-name"])
	if err != nil {
		return Action{}, false, err
	}
	tokenValue, err := compileValue(item.Attrs["token-value"])
	if err != nil {
		return Action{}, false, err
	}
	httpcode, err := compileValue(item.Attrs["failed-validation-httpcode"])
	if err != nil {
		return Action{}, false, err
	}
	message, err := compileValue(item.Attrs["failed-validation-error-message"])
	if err != nil {
		return Action{}, false, err
	}
	if strings.TrimSpace(tenantID) == "" || tokenValue != "" {
		return unsupported(item.Name), true, nil
	}
	constraints, source := compileTokenConstraints(item)
	if source != "" {
		return unsupported(source), true, nil
	}
	action := Action{Kind: ActionValidateJWT, Name: headerName, Variable: queryName, Value: message, Body: tenantID, FailedCode: http.StatusUnauthorized, Audiences: constraints.Audiences, Issuers: constraints.Issuers, ClientAppIDs: constraints.ClientAppIDs, Claims: constraints.Claims}
	if expression(httpcode) {
		action.Reason = httpcode
		action.FailedCode = 0
	} else if httpcode != "" {
		code := 0
		if _, err := fmt.Sscanf(httpcode, "%d", &code); err != nil {
			return Action{}, false, fmt.Errorf("invalid validate-azure-ad-token status")
		}
		action.FailedCode = code
	}
	return action, true, nil
}

type tokenConstraints struct {
	Audiences    []string
	Issuers      []string
	ClientAppIDs []string
	Claims       []ClaimConstraint
}

func compileTokenConstraints(item node) (tokenConstraints, string) {
	var result tokenConstraints
	for _, child := range item.Children {
		switch child.Name {
		case "openid-config":
			return tokenConstraints{}, item.Name + "/openid-config"
		case "audience":
			if text := strings.TrimSpace(child.Text); text != "" {
				result.Audiences = append(result.Audiences, text)
			}
		case "audiences":
			values, bad := childTexts(child, "audience")
			if bad != "" {
				return tokenConstraints{}, item.Name + "/audiences/" + bad
			}
			result.Audiences = append(result.Audiences, values...)
		case "issuer":
			if text := strings.TrimSpace(child.Text); text != "" {
				result.Issuers = append(result.Issuers, text)
			}
		case "issuers":
			values, bad := childTexts(child, "issuer")
			if bad != "" {
				return tokenConstraints{}, item.Name + "/issuers/" + bad
			}
			result.Issuers = append(result.Issuers, values...)
		case "required-claims":
			for _, claim := range child.Children {
				if claim.Name != "claim" {
					return tokenConstraints{}, item.Name + "/required-claims/" + claim.Name
				}
				name := strings.TrimSpace(claim.Attrs["name"])
				if name == "" {
					return tokenConstraints{}, item.Name + "/required-claims/claim"
				}
				values, bad := childTexts(claim, "value")
				if bad != "" {
					return tokenConstraints{}, item.Name + "/required-claims/claim/" + bad
				}
				match := strings.ToLower(strings.TrimSpace(claim.Attrs["match"]))
				if match != "" && match != "all" && match != "any" {
					return tokenConstraints{}, item.Name + "/required-claims/claim"
				}
				result.Claims = append(result.Claims, ClaimConstraint{Name: name, Values: values, MatchAny: match == "any", Separator: claim.Attrs["separator"]})
			}
		case "client-application-ids":
			if item.Name != "validate-azure-ad-token" {
				return tokenConstraints{}, item.Name + "/client-application-ids"
			}
			values, bad := childTexts(child, "application-id")
			if bad != "" {
				return tokenConstraints{}, item.Name + "/client-application-ids/" + bad
			}
			result.ClientAppIDs = append(result.ClientAppIDs, values...)
		default:
			return tokenConstraints{}, item.Name + "/" + child.Name
		}
	}
	return result, ""
}

func childTexts(item node, want string) ([]string, string) {
	var values []string
	for _, child := range item.Children {
		if child.Name != want {
			return nil, child.Name
		}
		if text := strings.TrimSpace(child.Text); text != "" {
			values = append(values, text)
		}
	}
	return values, ""
}

func compileSendRequest(item node) (Action, bool, error) {
	kind := ActionSendRequest
	mode, timeout := "", ""
	if item.Name == "send-one-way-request" {
		kind = ActionSendOneWay
		var err error
		mode, err = compileValue(item.Attrs["mode"])
		if err != nil {
			return Action{}, false, err
		}
		timeout, err = compileValue(item.Attrs["timeout"])
		if err != nil {
			return Action{}, false, err
		}
		if mode != "" && !expression(mode) && !strings.EqualFold(mode, "new") {
			return unsupported(item.Name), true, nil
		}
	}
	action := Action{Kind: kind, Name: mode, MaxAge: timeout, SendMethod: http.MethodGet, ResponseVar: item.Attrs["response-variable-name"]}
	if kind == ActionSendOneWay {
		action.ResponseVar = ""
	}
	for _, child := range item.Children {
		switch child.Name {
		case "set-url":
			value, err := compileValue(strings.TrimSpace(child.Text))
			if err != nil {
				return Action{}, false, err
			}
			action.SendURL = value
		case "set-method":
			value, err := compileValue(strings.TrimSpace(child.Text))
			if err != nil {
				return Action{}, false, err
			}
			action.SendMethod = value
		case "set-header":
			value, err := compileValue(childText(child, "value"))
			if err != nil {
				return Action{}, false, err
			}
			action.Headers = append(action.Headers, Header{Name: child.Attrs["name"], Value: value, Action: child.Attrs["exists-action"]})
		case "set-body":
			body := strings.TrimSpace(child.Text)
			if body == "" {
				body = childText(child, "value")
			}
			body, err := compileValue(body)
			if err != nil {
				return Action{}, false, err
			}
			action.Body = body
		default:
			return unsupported(item.Name + "/" + child.Name), true, nil
		}
	}
	if action.SendURL == "" || action.SendMethod == "" {
		return unsupported(item.Name), true, nil
	}
	return action, true, nil
}

func writeNodeXML(body *strings.Builder, item node) {
	body.WriteByte('<')
	body.WriteString(item.Name)
	keys := make([]string, 0, len(item.Attrs))
	for key := range item.Attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		body.WriteByte(' ')
		body.WriteString(key)
		body.WriteString(`="`)
		body.WriteString(item.Attrs[key])
		body.WriteByte('"')
	}
	if item.Text == "" && len(item.Children) == 0 {
		body.WriteString("/>")
		return
	}
	body.WriteByte('>')
	body.WriteString(item.Text)
	for _, child := range item.Children {
		writeNodeXML(body, child)
	}
	body.WriteString("</")
	body.WriteString(item.Name)
	body.WriteByte('>')
}

func enforceTokenConstraints(action Action, token string) bool {
	if len(action.Audiences)+len(action.Issuers)+len(action.ClientAppIDs)+len(action.Claims) == 0 {
		return true
	}
	claims, err := jwtPayload(token)
	if err != nil {
		return false
	}
	if len(action.Issuers) > 0 && !containsAny(claimStrings(claims["iss"], ""), action.Issuers) {
		return false
	}
	if len(action.Audiences) > 0 && !containsAny(claimStrings(claims["aud"], ""), action.Audiences) {
		return false
	}
	if len(action.ClientAppIDs) > 0 {
		apps := append(claimStrings(claims["appid"], ""), claimStrings(claims["azp"], "")...)
		if !containsAny(apps, action.ClientAppIDs) {
			return false
		}
	}
	for _, constraint := range action.Claims {
		if !matchClaimValues(claimStrings(claims[constraint.Name], constraint.Separator), constraint.Values, constraint.MatchAny) {
			return false
		}
	}
	return true
}

func jwtPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func claimStrings(value any, separator string) []string {
	var raw []string
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		raw = []string{typed}
	case float64:
		raw = []string{strconv.FormatFloat(typed, 'f', -1, 64)}
	case bool:
		raw = []string{strconv.FormatBool(typed)}
	case []any:
		for _, item := range typed {
			raw = append(raw, claimStrings(item, "")...)
		}
	default:
		raw = []string{fmt.Sprint(typed)}
	}
	if separator == "" {
		return raw
	}
	var split []string
	for _, item := range raw {
		for _, part := range strings.Split(item, separator) {
			if part = strings.TrimSpace(part); part != "" {
				split = append(split, part)
			}
		}
	}
	return split
}

func containsAny(actual, allowed []string) bool {
	for _, have := range actual {
		for _, want := range allowed {
			if have == want {
				return true
			}
		}
	}
	return false
}

func matchClaimValues(actual, required []string, matchAny bool) bool {
	if len(required) == 0 {
		return !matchAny
	}
	if matchAny {
		return containsAny(actual, required)
	}
	for _, want := range required {
		found := false
		for _, have := range actual {
			if have == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func tokenFromRequest(request *http.Request, action Action) string {
	if action.Variable != "" {
		if request.URL == nil {
			return ""
		}
		return strings.TrimSpace(request.URL.Query().Get(action.Variable))
	}
	name := action.Name
	if name == "" {
		name = "Authorization"
	}
	return strings.TrimSpace(strings.TrimPrefix(request.Header.Get(name), "Bearer "))
}

func requestBaseURL(request *http.Request) string {
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	if request.URL != nil && request.URL.Scheme != "" {
		scheme = request.URL.Scheme
	}
	host := request.Host
	if host == "" && request.URL != nil {
		host = request.URL.Host
	}
	return scheme + "://" + host
}

func replaceContentURLs(state *State, gateway, backend string) error {
	from, to := gateway, backend
	if state.Response != nil {
		from, to = backend, gateway
	}
	var body io.ReadCloser
	if state.Response != nil {
		body = state.Response.Body
	} else {
		body = state.Request.Body
	}
	if body == nil {
		return fmt.Errorf("redirect-content-urls requires a body")
	}
	value, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	replaced := strings.ReplaceAll(string(value), from, to)
	if state.Response != nil {
		state.Response.Body = io.NopCloser(strings.NewReader(replaced))
		return nil
	}
	state.Request.Body = io.NopCloser(strings.NewReader(replaced))
	state.Request.ContentLength = int64(len(replaced))
	state.Request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(replaced)), nil
	}
	return nil
}

func unsupported(name string) Action { return Action{Kind: ActionUnsupported, Source: name} }
func expression(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "@(") || strings.HasPrefix(value, "@{")
}

func compileValue(value string) (string, error) {
	if !expression(value) {
		return value, nil
	}
	if _, _, err := expr.Parse(value); err != nil {
		return "", fmt.Errorf("invalid expression: %w", err)
	}
	return value, nil
}

func evalValue(value string, state *State) (string, error) {
	if !expression(value) {
		return value, nil
	}
	got, err := expr.EvalEnv(value, stateEnv(state))
	if err != nil {
		return "", err
	}
	return got.String(), nil
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
			value, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			target := state.Headers
			if state.Response == nil && state.Request != nil {
				target = state.Request.Header
			}
			setHeader(target, Header{Name: action.Name, Value: value, Action: action.Action})
		case ActionBase:
			// Base markers are expanded by the gateway scope composer.
		case ActionSetQueryParameter:
			if state.Request == nil {
				return fmt.Errorf("set-query-parameter requires a request")
			}
			value, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			query := state.Request.URL.Query()
			switch action.Action {
			case "delete":
				query.Del(action.Name)
			case "skip":
				if !query.Has(action.Name) {
					query.Set(action.Name, value)
				}
			default:
				query.Set(action.Name, value)
			}
			state.Request.URL.RawQuery = query.Encode()
		case ActionGetAuthorizationContext:
			if state.FetchCredential == nil {
				return fmt.Errorf("get-authorization-context requires a configured credential store")
			}
			credential, err := state.FetchCredential(action.Name, action.Value)
			if err != nil {
				// ignore-error="true" is the documented way to let a request
				// proceed uncredentialed, so the policy can decide what an
				// unauthenticated call should do. Without it the failure stops
				// the pipeline, which is the safe default: a backend call that
				// silently loses its credential looks like an authorization
				// bug in the backend.
				if action.IgnoreCase {
					continue
				}
				return err
			}
			if state.AuthorizationContexts == nil {
				state.AuthorizationContexts = map[string]expr.AuthorizationContext{}
			}
			state.AuthorizationContexts[action.Variable] = credential
		case ActionSetVariable:
			value, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			if state.Variables == nil {
				state.Variables = map[string]string{}
			}
			state.Variables[action.Variable] = value
		case ActionSetBody:
			body, err := evalValue(action.Body, state)
			if err != nil {
				return err
			}
			if state.Response == nil && state.Request != nil {
				state.Request.Body = io.NopCloser(strings.NewReader(body))
				state.Request.ContentLength = int64(len(body))
				state.Request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(body)), nil
				}
			} else {
				state.Body, state.BodySet = body, true
			}
		case ActionCheckHeader:
			if state.Request == nil {
				return fmt.Errorf("check-header requires a request")
			}
			name, err := evalValue(action.Name, state)
			if err != nil {
				return err
			}
			values := make([]string, len(action.Values))
			for i, allowed := range action.Values {
				value, err := evalValue(allowed, state)
				if err != nil {
					return err
				}
				values[i] = value
			}
			message, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			actual := state.Request.Header.Values(name)
			matched := false
			for _, candidate := range actual {
				for _, allowed := range values {
					if (action.IgnoreCase && strings.EqualFold(candidate, allowed)) || (!action.IgnoreCase && candidate == allowed) {
						matched = true
					}
				}
			}
			if !matched {
				state.Returned, state.StatusCode, state.Body = true, action.StatusCode, message
				return nil
			}
		case ActionValidateJWT:
			if state.Request == nil || state.ValidateToken == nil {
				return fmt.Errorf("validate-jwt requires a configured token validator")
			}
			if action.Body != "" {
				tenantID, err := evalValue(action.Body, state)
				if err != nil {
					return err
				}
				if strings.TrimSpace(tenantID) == "" {
					return fmt.Errorf("validate-azure-ad-token requires a tenant-id")
				}
			}
			headerName, err := evalValue(action.Name, state)
			if err != nil {
				return err
			}
			queryName, err := evalValue(action.Variable, state)
			if err != nil {
				return err
			}
			code := action.FailedCode
			if action.Reason != "" {
				evaluated, err := evalValue(action.Reason, state)
				if err != nil {
					return err
				}
				if _, err := fmt.Sscanf(evaluated, "%d", &code); err != nil || code < 100 || code > 599 {
					return fmt.Errorf("invalid validate-azure-ad-token status")
				}
			}
			message, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			token := tokenFromRequest(state.Request, Action{Name: headerName, Variable: queryName})
			if state.ValidateToken(token) != nil || !enforceTokenConstraints(action, token) {
				state.Returned, state.StatusCode, state.Body = true, code, message
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
			value, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			state.Request.Method = strings.ToUpper(value)
		case ActionCORS:
			if state.Request == nil {
				return fmt.Errorf("cors requires a request")
			}
			origin := state.Request.Header.Get("Origin")
			if origin == "" {
				continue
			}
			allowOrigin, err := evalValue(action.AllowOrigin, state)
			if err != nil {
				return err
			}
			methods, err := evalValue(action.Methods, state)
			if err != nil {
				return err
			}
			allowHeaders, err := evalValue(action.AllowHeaders, state)
			if err != nil {
				return err
			}
			exposeHeaders, err := evalValue(action.ExposeHeaders, state)
			if err != nil {
				return err
			}
			maxAge, err := evalValue(action.MaxAge, state)
			if err != nil {
				return err
			}
			state.Headers.Set("Access-Control-Allow-Origin", allowOrigin)
			if action.AllowCreds {
				state.Headers.Set("Access-Control-Allow-Credentials", "true")
			}
			if methods != "" {
				state.Headers.Set("Access-Control-Allow-Methods", methods)
			}
			if allowHeaders != "" {
				state.Headers.Set("Access-Control-Allow-Headers", allowHeaders)
			}
			if exposeHeaders != "" {
				state.Headers.Set("Access-Control-Expose-Headers", exposeHeaders)
			}
			if maxAge != "" {
				state.Headers.Set("Access-Control-Max-Age", maxAge)
			}
			if state.Request.Method == http.MethodOptions {
				state.Returned, state.StatusCode = true, http.StatusNoContent
			}
		case ActionSendRequest, ActionSendOneWay:
			if state.SendRequest == nil {
				if action.Kind == ActionSendOneWay {
					return fmt.Errorf("send-one-way-request requires a configured transport")
				}
				return fmt.Errorf("send-request requires a configured transport")
			}
			if action.Kind == ActionSendOneWay {
				mode, err := evalValue(action.Name, state)
				if err != nil {
					return err
				}
				if mode != "" && !strings.EqualFold(mode, "new") {
					return fmt.Errorf("%w: <send-one-way-request>", ErrUnsupported)
				}
				if _, err := evalValue(action.MaxAge, state); err != nil {
					return err
				}
			}
			sendURL, err := evalValue(action.SendURL, state)
			if err != nil {
				return err
			}
			sendMethod, err := evalValue(action.SendMethod, state)
			if err != nil {
				return err
			}
			body, err := evalValue(action.Body, state)
			if err != nil {
				return err
			}
			request, err := http.NewRequest(strings.ToUpper(sendMethod), sendURL, strings.NewReader(body))
			if err != nil {
				return err
			}
			for _, header := range action.Headers {
				value, err := evalValue(header.Value, state)
				if err != nil {
					return err
				}
				setHeader(request.Header, Header{Name: header.Name, Value: value, Action: header.Action})
			}
			response, err := state.SendRequest(request)
			if action.Kind == ActionSendOneWay {
				if response != nil && response.Body != nil {
					_ = response.Body.Close()
				}
				continue
			}
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
			if err := executeLimit(action, state); err != nil {
				return err
			}
			if state.Returned {
				return nil
			}
		case ActionLimitConcurrency:
			if state.AcquireConcurrency == nil {
				return fmt.Errorf("limit-concurrency requires a configured limiter")
			}
			key, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			if key == "" && state.Request != nil {
				key = state.Request.RemoteAddr
			}
			release := state.AcquireConcurrency(key, action.LimitCalls)
			if release == nil {
				state.Returned, state.StatusCode, state.Body = true, action.StatusCode, action.Body
				return nil
			}
			state.ConcurrencyReleases = append(state.ConcurrencyReleases, release)
			if err := Execute(action.Children, state); err != nil {
				return err
			}
			if state.Returned {
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
			username, err := evalValue(action.AuthUsername, state)
			if err != nil {
				return err
			}
			password, err := evalValue(action.AuthPassword, state)
			if err != nil {
				return err
			}
			state.Request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
		case ActionAuthenticationManagedIdentity:
			if state.Request == nil {
				return fmt.Errorf("authentication-managed-identity requires a request")
			}
			if state.AcquireToken == nil {
				return fmt.Errorf("authentication-managed-identity requires a token provider")
			}
			resource, err := evalValue(action.AuthResource, state)
			if err != nil {
				return err
			}
			token, err := state.AcquireToken(resource)
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
			clientID, err := evalValue(action.AuthClientID, state)
			if err != nil {
				return err
			}
			clientSecret, err := evalValue(action.AuthClientSecret, state)
			if err != nil {
				return err
			}
			endpoint, err := evalValue(action.AuthTokenEndpoint, state)
			if err != nil {
				return err
			}
			resource, err := evalValue(action.AuthResource, state)
			if err != nil {
				return err
			}
			token, err := state.AcquireOAuth2Token(clientID, clientSecret, endpoint, resource)
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
			certificateID, err := evalValue(action.AuthCertificateID, state)
			if err != nil {
				return err
			}
			if err := state.AttachClientCertificate(state.Request, certificateID); err != nil {
				return err
			}
		case ActionFindReplace:
			from, err := evalValue(action.ReplaceFrom, state)
			if err != nil {
				return err
			}
			to, err := evalValue(action.ReplaceTo, state)
			if err != nil {
				return err
			}
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
			replaced := strings.ReplaceAll(string(value), from, to)
			if state.Response != nil {
				state.Response.Body = io.NopCloser(strings.NewReader(replaced))
			} else {
				state.Request.Body = io.NopCloser(strings.NewReader(replaced))
				state.Request.ContentLength = int64(len(replaced))
				state.Request.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(replaced)), nil }
			}
		case ActionJSONToXML:
			if state.Response == nil {
				return fmt.Errorf("json-to-xml requires a response")
			}
			root, err := evalValue(action.TransformRoot, state)
			if err != nil {
				return err
			}
			value, err := io.ReadAll(state.Response.Body)
			if err != nil {
				return err
			}
			var document any
			if err := json.Unmarshal(value, &document); err != nil {
				return err
			}
			xmlValue, err := jsonValueXML(root, document)
			if err != nil {
				return err
			}
			state.Response.Body = io.NopCloser(strings.NewReader(xmlValue))
		case ActionXMLToJSON:
			if state.Response == nil {
				return fmt.Errorf("xml-to-json requires a response")
			}
			value, err := io.ReadAll(state.Response.Body)
			if err != nil {
				return err
			}
			var document node
			if err := xml.Unmarshal(value, &document); err != nil {
				return err
			}
			jsonValue, _ := json.Marshal(map[string]any{document.Name: xmlNodeJSON(document)})
			state.Response.Body = io.NopCloser(strings.NewReader(string(jsonValue)))
		case ActionJSONP:
			if state.Response == nil || state.Request == nil || state.Request.URL == nil {
				return fmt.Errorf("jsonp requires a request and response")
			}
			parameter, err := evalValue(action.JSONPParameter, state)
			if err != nil {
				return err
			}
			callback := state.Request.URL.Query().Get(parameter)
			if callback == "" {
				continue
			}
			value, err := io.ReadAll(state.Response.Body)
			if err != nil {
				return err
			}
			state.Response.Body = io.NopCloser(strings.NewReader(callback + "(" + string(value) + ");"))
		case ActionCacheLookupValue:
			if state.ValueCacheGet == nil {
				return fmt.Errorf("cache-lookup-value requires a cache")
			}
			key, err := evalValue(action.ValueCacheKey, state)
			if err != nil {
				return err
			}
			variable, err := evalValue(action.Variable, state)
			if err != nil {
				return err
			}
			if variable == "" {
				return fmt.Errorf("cache-lookup-value requires a variable-name")
			}
			value, ok := state.ValueCacheGet(key)
			if ok {
				if state.Variables == nil {
					state.Variables = map[string]string{}
				}
				state.Variables[variable] = value
			}
		case ActionCacheStoreValue:
			if state.ValueCacheSet == nil {
				return fmt.Errorf("cache-store-value requires a cache")
			}
			key, err := evalValue(action.ValueCacheKey, state)
			if err != nil {
				return err
			}
			value, err := evalValue(action.ValueCacheValue, state)
			if err != nil {
				return err
			}
			state.ValueCacheSet(key, value, action.ValueCacheDuration)
		case ActionCacheRemoveValue:
			if state.ValueCacheRemove == nil {
				return fmt.Errorf("cache-remove-value requires a cache")
			}
			key, err := evalValue(action.ValueCacheKey, state)
			if err != nil {
				return err
			}
			state.ValueCacheRemove(key)
		case ActionSetBackend:
			value, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			backendID, err := evalValue(action.BackendID, state)
			if err != nil {
				return err
			}
			state.BackendURL = value
			state.BackendID = backendID
		case ActionRewriteURI:
			value, err := evalValue(action.Value, state)
			if err != nil {
				return err
			}
			state.Path = value
		case ActionForward:
			// Forwarding is performed by the gateway after the backend section.
		case ActionReturnResponse:
			code := action.StatusCode
			if action.Value != "" {
				evaluated, err := evalValue(action.Value, state)
				if err != nil {
					return err
				}
				if _, err := fmt.Sscanf(evaluated, "%d", &code); err != nil || code < 100 || code > 599 {
					return fmt.Errorf("invalid mock-response status-code")
				}
			}
			body, err := evalValue(action.Body, state)
			if err != nil {
				return err
			}
			state.Returned, state.StatusCode, state.Reason, state.Body = true, code, action.Reason, body
			for _, header := range action.Headers {
				value, err := evalValue(header.Value, state)
				if err != nil {
					return err
				}
				setHeader(state.Headers, Header{Name: header.Name, Value: value, Action: header.Action})
			}
			return nil
		case ActionSetStatus:
			code := action.StatusCode
			if action.Value != "" {
				evaluated, err := evalValue(action.Value, state)
				if err != nil {
					return err
				}
				if _, err := fmt.Sscanf(evaluated, "%d", &code); err != nil || code < 100 || code > 599 {
					return fmt.Errorf("invalid set-status code")
				}
			}
			reason, err := evalValue(action.Reason, state)
			if err != nil {
				return err
			}
			state.StatusCode = code
			state.Reason = reason
		case ActionRedirectContentURLs:
			if state.Request == nil || state.BackendURL == "" {
				return fmt.Errorf("redirect-content-urls requires a request and backend URL")
			}
			if err := replaceContentURLs(state, requestBaseURL(state.Request), strings.TrimRight(state.BackendURL, "/")); err != nil {
				return err
			}
		case ActionRetry:
			if err := Execute(action.Children, state); err != nil {
				return err
			}
		case ActionWait:
			if err := executeWait(action, state); err != nil {
				return err
			}
		case ActionUnsupported:
			return fmt.Errorf("%w: <%s>", ErrUnsupported, action.Source)
		}
	}
	return nil
}

func executeLimit(action Action, state *State) error {
	key, err := evalValue(action.Value, state)
	if err != nil {
		return err
	}
	if key == "" && state.Request != nil {
		key = state.Request.RemoteAddr
	}
	if action.LimitCalls > 0 {
		if state.RateLimit == nil {
			return fmt.Errorf("rate-limit requires a configured limiter")
		}
		if state.RateLimit(key, action.LimitCalls, action.LimitPeriod) {
			return limitExceeded(action, state)
		}
	}
	if action.LimitBandwidth > 0 {
		if state.BandwidthLimit == nil {
			return fmt.Errorf("quota bandwidth requires a configured limiter")
		}
		if state.BandwidthLimit(key, requestSize(state), action.LimitBandwidth, action.LimitPeriod) {
			return limitExceeded(action, state)
		}
	}
	if err := Execute(action.Children, state); err != nil {
		return err
	}
	return nil
}

func limitExceeded(action Action, state *State) error {
	state.Returned, state.StatusCode = true, action.StatusCode
	if action.Body != "" {
		state.Headers.Set(action.Body, "true")
	}
	return nil
}

func requestSize(state *State) int64 {
	if state.Request == nil {
		return 0
	}
	if state.Request.ContentLength > 0 {
		return state.Request.ContentLength
	}
	if state.Request.Body == nil && state.Request.GetBody == nil {
		return 0
	}
	var body io.ReadCloser
	var err error
	if state.Request.GetBody != nil {
		body, err = state.Request.GetBody()
		if err != nil {
			return 0
		}
	} else {
		body = state.Request.Body
	}
	value, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		return 0
	}
	if state.Request.GetBody == nil {
		state.Request.Body = io.NopCloser(strings.NewReader(string(value)))
		state.Request.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(string(value))), nil
		}
		state.Request.ContentLength = int64(len(value))
	}
	return int64(len(value))
}

func executeWait(action Action, state *State) error {
	if action.Action != "any" {
		return Execute(action.Children, state)
	}
	if len(action.Children) == 0 {
		return nil
	}
	var last error
	for _, child := range action.Children {
		if err := Execute([]Action{child}, state); err != nil {
			last = err
			continue
		}
		return nil
	}
	return last
}

func stateEnv(state *State) *expr.Env {
	return expr.Bind(expr.Context{
		Request:               state.Request,
		Response:              state.Response,
		Variables:             state.Variables,
		LastError:             state.LastError,
		Api:                   state.Api,
		Operation:             state.Operation,
		Product:               state.Product,
		Subscription:          state.Subscription,
		User:                  state.User,
		Deployment:            state.Deployment,
		GraphQL:               state.GraphQL,
		AuthorizationContexts: state.AuthorizationContexts,
	})
}

func evaluateCondition(condition string, state *State) (bool, error) {
	value, err := expr.EvalEnv(condition, stateEnv(state))
	if err != nil {
		return false, err
	}
	truth, ok := value.AsBool()
	if !ok {
		return false, fmt.Errorf("choose condition must be boolean")
	}
	return truth, nil
}

func jsonValueXML(name string, value any) (string, error) {
	var builder strings.Builder
	var write func(string, any) error
	write = func(tag string, item any) error {
		if tag == "" {
			return fmt.Errorf("json-to-xml element name is empty")
		}
		builder.WriteString("<" + tag + ">")
		switch typed := item.(type) {
		case map[string]any:
			for key, child := range typed {
				if err := write(key, child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := write("item", child); err != nil {
					return err
				}
			}
		case nil:
		default:
			value := fmt.Sprint(typed)
			_ = xml.EscapeText(&builder, []byte(value))
		}
		builder.WriteString("</" + tag + ">")
		return nil
	}
	if err := write(name, value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func xmlNodeJSON(value node) any {
	if len(value.Children) == 0 {
		return strings.TrimSpace(value.Text)
	}
	result := map[string]any{}
	for _, child := range value.Children {
		item := xmlNodeJSON(child)
		if existing, ok := result[child.Name]; ok {
			if items, ok := existing.([]any); ok {
				result[child.Name] = append(items, item)
			} else {
				result[child.Name] = []any{existing, item}
			}
		} else {
			result[child.Name] = item
		}
	}
	return result
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
