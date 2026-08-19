package expression

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ApiContext is the documented scalar API identity.
type ApiContext struct {
	Id   string
	Name string
	Path string
	// Revision, Version and IsCurrentRevision describe WHICH api this is among
	// its revisions and versions. A policy routing on them is the reason APIM
	// exposes them at all.
	Revision          string
	Version           string
	IsCurrentRevision bool
	ServiceUrl        string
}

// OperationContext is the documented scalar operation identity.
type OperationContext struct {
	Id          string
	Name        string
	Method      string
	UrlTemplate string
}

// DeploymentContext is the documented scalar deployment identity.
type DeploymentContext struct {
	ServiceName string
	Region      string
	ServiceId   string
	GatewayId   string
	// Gateway describes the gateway serving this request. It is null on the
	// managed gateway in Azure only for older platform versions; here it is
	// always present, and IsManaged distinguishes the built-in gateway from a
	// self-hosted one.
	Gateway *GatewayContext
}

// GatewayContext is the documented identity of the gateway serving a request.
type GatewayContext struct {
	Id         string
	InstanceId string
	IsManaged  bool
}

// ProductContext is the documented product identity.
//
// Separate from the user context, rather than one struct for all three, because Azure's
// IProduct and IUser are different types: one struct carrying both would let a
// policy read a product field off a user and get an empty string instead of an
// error.
type ProductContext struct {
	Id                   string
	Name                 string
	State                string
	ApprovalRequired     bool
	SubscriptionRequired bool
	SubscriptionsLimit   Value
	// Groups and Apis are what the product grants access to. Empty rather than
	// nil-checked at every read: a product with no groups is a product a policy
	// can still ask about.
	Groups []GroupContext
	Apis   []ApiContext
}

// UserContext is the documented developer identity.
//
// Its own type, for the same reason Product and
// Subscription have theirs: IUser has members the others do not, and one struct
// carrying all of them lets a policy read a product field off a user.
type UserContext struct {
	Id               string
	Email            string
	FirstName        string
	LastName         string
	Note             string
	RegistrationDate string
	Groups           []GroupContext
	Identities       []UserIdentityContext
}

// SubscriptionContext is the documented subscription identity.
//
// The keys are here because Azure puts them here: a policy may read
// `context.Subscription.Key` to key a rate limit by caller. They are the same
// secrets the management plane refuses to echo on a GET, which is not a
// contradiction -- a policy already runs on behalf of the service.
type SubscriptionContext struct {
	Id           string
	Name         string
	Key          string
	PrimaryKey   string
	SecondaryKey string
	CreatedDate  string
	StartDate    string
	EndDate      string
}

// Context is the APIM `context` binding for one evaluation.
type Context struct {
	Request      *http.Request
	Response     *http.Response
	Variables    map[string]string
	LastError    error
	Api          *ApiContext
	Operation    *OperationContext
	Product      *ProductContext
	Subscription *SubscriptionContext
	User         *UserContext
	Deployment   *DeploymentContext
	// Timestamp is when the gateway received the request, and Elapsed is
	// measured from it. Both are zero outside a request, where `context` still
	// binds so a literal expression can be evaluated.
	Timestamp time.Time
	// Elapsed is supplied as a function rather than a value because a policy
	// reading it in the outbound section must see the time spent so far, not
	// the time when the context was built.
	Elapsed func() time.Duration
	// RequestId is the gateway's own correlation id for this request.
	RequestId string
	// Tracing reports whether the caller asked for a trace.
	Tracing bool
	// LastErrorLocation is where LastError happened, when the failure came from
	// the policy engine. Nil for any other error, which is why every member but
	// Message reads empty rather than inventing a position.
	LastErrorLocation ErrorLocation
	// OriginalUrl is the URL as the CALLER sent it, before any policy rewrote
	// it. A policy that logs or routes on where a request was actually aimed
	// needs the original, not the one it just changed.
	OriginalUrl string
	// MatchedParameters are the values the operation's URL template captured,
	// which is how a policy reads `{orderId}` out of the path.
	MatchedParameters map[string]string
	// Certificates are the service's client certificates, keyed by the name
	// they were uploaded under.
	Certificates map[string]*x509.Certificate
	// AuthorizationContexts are credential-manager results, keyed by the
	// variable name the policy stored them under. They ride alongside
	// Variables rather than inside it because Variables is map[string]string
	// and a credential is an object: `context.Variables["x"].AccessToken` has
	// to resolve a member, which a string cannot answer.
	AuthorizationContexts map[string]AuthorizationContext
	// GraphQL is bound only while a GraphQL resolver's policy is running. It
	// is null everywhere else, so `context.GraphQL` in an inbound policy
	// evaluates to null rather than to an empty argument set that would read
	// as "the caller passed nothing".
	GraphQL *GraphQLContext
}

// Bind builds the identifier environment for an APIM context. Missing request,
// response, or last-error values still bind `context` so literal expressions
// evaluate; member access on a missing object fails at the member.
func Bind(ctx Context) *Env {
	return &Env{Bindings: map[string]Value{
		"context": Object(&contextHost{ctx: ctx}),
	}}
}

// RequestEnv binds request and variables only. Prefer Bind when response or
// last-error members are required.
func RequestEnv(request *http.Request, variables map[string]string) *Env {
	return Bind(Context{Request: request, Variables: variables})
}

type contextHost struct {
	ctx Context
}

func (c *contextHost) member(name string) (Value, error) {
	switch name {
	case "Request":
		if c.ctx.Request == nil {
			return Null(), nil
		}
		return Object(&requestHost{request: c.ctx.Request, originalUrl: c.ctx.OriginalUrl, matched: c.ctx.MatchedParameters}), nil
	case "Response":
		if c.ctx.Response == nil {
			return Null(), nil
		}
		return Object(&responseHost{response: c.ctx.Response}), nil
	case "Variables":
		return Object(&mapHost{values: c.ctx.Variables, objects: c.ctx.AuthorizationContexts}), nil
	case "LastError":
		if c.ctx.LastError == nil {
			return Null(), nil
		}
		return Object(&lastErrorHost{err: c.ctx.LastError, located: c.ctx.LastErrorLocation}), nil
	case "Api":
		if c.ctx.Api == nil {
			return Null(), nil
		}
		return Object(&apiHost{ctx: c.ctx.Api}), nil
	case "Operation":
		if c.ctx.Operation == nil {
			return Null(), nil
		}
		return Object(&operationHost{id: c.ctx.Operation.Id, name: c.ctx.Operation.Name, method: c.ctx.Operation.Method, urlTemplate: c.ctx.Operation.UrlTemplate}), nil
	case "Product":
		if c.ctx.Product == nil {
			return Null(), nil
		}
		return Object(&productHost{ctx: c.ctx.Product}), nil
	case "Subscription":
		if c.ctx.Subscription == nil {
			return Null(), nil
		}
		return Object(&subscriptionHost{ctx: c.ctx.Subscription}), nil
	case "User":
		if c.ctx.User == nil {
			return Null(), nil
		}
		return Object(&userHost{ctx: c.ctx.User}), nil
	case "Deployment":
		if c.ctx.Deployment == nil {
			return Null(), nil
		}
		return Object(&deploymentHost{ctx: c.ctx.Deployment, certificates: c.ctx.Certificates}), nil
	case "Timestamp":
		return String(c.ctx.Timestamp.UTC().Format(time.RFC3339)), nil
	case "Elapsed":
		if c.ctx.Elapsed == nil {
			return String("00:00:00"), nil
		}
		return String(formatElapsed(c.ctx.Elapsed())), nil
	case "RequestId":
		return String(c.ctx.RequestId), nil
	case "Tracing":
		return Bool(c.ctx.Tracing), nil
	case "GraphQL":
		if c.ctx.GraphQL == nil {
			return Null(), nil
		}
		return Object(&graphQLHost{ctx: c.ctx.GraphQL}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type apiHost struct {
	ctx *ApiContext
}

func (h *apiHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.ctx.Id), nil
	case "Name":
		return String(h.ctx.Name), nil
	case "Path":
		return String(h.ctx.Path), nil
	case "Revision":
		return String(h.ctx.Revision), nil
	case "Version":
		return String(h.ctx.Version), nil
	case "IsCurrentRevision":
		return Bool(h.ctx.IsCurrentRevision), nil
	case "ServiceUrl":
		return String(h.ctx.ServiceUrl), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type productHost struct {
	ctx *ProductContext
}

func (h *productHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.ctx.Id), nil
	case "Name":
		return String(h.ctx.Name), nil
	case "State":
		return String(h.ctx.State), nil
	case "ApprovalRequired":
		return Bool(h.ctx.ApprovalRequired), nil
	case "SubscriptionRequired":
		return Bool(h.ctx.SubscriptionRequired), nil
	case "Groups":
		return groupList(h.ctx.Groups), nil
	case "Apis":
		return apiList(h.ctx.Apis), nil
	case "SubscriptionsLimit":
		// Null rather than zero when the product sets no limit: Azure types this
		// as a nullable int, and reporting 0 would read as "no subscriptions
		// allowed", which is the opposite of "unlimited".
		return h.ctx.SubscriptionsLimit, nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type userHost struct {
	ctx *UserContext
}

func (h *userHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.ctx.Id), nil
	case "Email":
		return String(h.ctx.Email), nil
	case "FirstName":
		return String(h.ctx.FirstName), nil
	case "LastName":
		return String(h.ctx.LastName), nil
	case "Note":
		return String(h.ctx.Note), nil
	case "RegistrationDate":
		return String(h.ctx.RegistrationDate), nil
	case "Groups":
		return groupList(h.ctx.Groups), nil
	case "Identities":
		return identityList(h.ctx.Identities), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type subscriptionHost struct {
	ctx *SubscriptionContext
}

func (h *subscriptionHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.ctx.Id), nil
	case "Name":
		return String(h.ctx.Name), nil
	case "Key":
		return String(h.ctx.Key), nil
	case "PrimaryKey":
		return String(h.ctx.PrimaryKey), nil
	case "SecondaryKey":
		return String(h.ctx.SecondaryKey), nil
	case "CreatedDate":
		return String(h.ctx.CreatedDate), nil
	case "StartDate":
		return String(h.ctx.StartDate), nil
	case "EndDate":
		return String(h.ctx.EndDate), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type gatewayHost struct {
	ctx *GatewayContext
}

func (h *gatewayHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.ctx.Id), nil
	case "InstanceId":
		return String(h.ctx.InstanceId), nil
	case "IsManaged":
		return Bool(h.ctx.IsManaged), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type operationHost struct {
	id          string
	name        string
	method      string
	urlTemplate string
}

func (h *operationHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.id), nil
	case "Name":
		return String(h.name), nil
	case "Method":
		return String(h.method), nil
	case "UrlTemplate":
		return String(h.urlTemplate), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type deploymentHost struct {
	ctx          *DeploymentContext
	certificates map[string]*x509.Certificate
}

func (h *deploymentHost) member(name string) (Value, error) {
	switch name {
	case "ServiceName":
		return String(h.ctx.ServiceName), nil
	case "Region":
		return String(h.ctx.Region), nil
	case "ServiceId":
		return String(h.ctx.ServiceId), nil
	case "GatewayId":
		return String(h.ctx.GatewayId), nil
	case "Gateway":
		if h.ctx.Gateway == nil {
			return Null(), nil
		}
		return Object(&gatewayHost{ctx: h.ctx.Gateway}), nil
	case "Certificates":
		return Object(&certificateMapHost{certificates: h.certificates}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// formatElapsed renders a duration the way .NET renders a TimeSpan, which is
// what a policy comparing against a literal will have been written for.
func formatElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	hours := int(d / time.Hour)
	minutes := int(d/time.Minute) % 60
	seconds := int(d/time.Second) % 60
	milliseconds := int(d/time.Millisecond) % 1000
	return fmt.Sprintf("%02d:%02d:%02d.%03d", hours, minutes, seconds, milliseconds)
}

type requestHost struct {
	request *http.Request
	// originalUrl and matched come from the context rather than the request,
	// because both describe what happened BEFORE a policy touched it.
	originalUrl string
	matched     map[string]string
}

func (r *requestHost) member(name string) (Value, error) {
	switch name {
	case "Method":
		return String(r.request.Method), nil
	// `Url`, and not `URL`. APIM expressions are C#, where member access is
	// case-sensitive, so `context.Request.URL` does not compile in Azure.
	// Accepting it here would let a policy be written locally that a tenant
	// refuses -- the leniency direction, which has no local symptom.
	case "Url":
		return Object(&urlHost{request: r.request}), nil
	case "Headers":
		return Object(&headerHost{header: r.request.Header}), nil
	case "IpAddress":
		return String(clientIP(r.request.RemoteAddr)), nil
	case "Body":
		return Object(&bodyHost{read: func() (string, error) { return readRequestBody(r.request) }}), nil
	case "OriginalUrl":
		if r.originalUrl == "" {
			// No rewrite happened, so the original IS the current URL. Returning
			// null would make a policy that logs OriginalUrl lose the common case.
			return Object(&urlHost{request: r.request}), nil
		}
		parsed, err := url.Parse(r.originalUrl)
		if err != nil {
			return Null(), fmt.Errorf("original url %q is unparsable: %w", r.originalUrl, err)
		}
		return Object(&urlHost{request: &http.Request{URL: parsed, Host: parsed.Host, TLS: r.request.TLS}}), nil
	case "MatchedParameters":
		return Object(&mapHost{values: r.matched}), nil
	case "Certificate":
		// Null when the caller presented none, which is what a policy tests
		// before reading a thumbprint off it.
		if r.request.TLS == nil || len(r.request.TLS.PeerCertificates) == 0 {
			return Null(), nil
		}
		return Object(&certificateHost{certificate: r.request.TLS.PeerCertificates[0]}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// certificateHost binds the members of an X509Certificate2 that APIM documents.
type certificateHost struct {
	certificate *x509.Certificate
}

func (c *certificateHost) member(name string) (Value, error) {
	switch name {
	case "Thumbprint":
		// Uppercase hex of the SHA-1 hash, which is the form Azure reports and
		// the form a policy compares an uploaded certificate's thumbprint to.
		sum := sha1.Sum(c.certificate.Raw)
		return String(strings.ToUpper(hex.EncodeToString(sum[:]))), nil
	case "Subject":
		return String(c.certificate.Subject.String()), nil
	case "Issuer":
		return String(c.certificate.Issuer.String()), nil
	case "SerialNumber":
		return String(c.certificate.SerialNumber.String()), nil
	case "NotBefore":
		return String(c.certificate.NotBefore.UTC().Format(time.RFC3339)), nil
	case "NotAfter":
		return String(c.certificate.NotAfter.UTC().Format(time.RFC3339)), nil
	case "Verify":
		// Validity only: this emulator has no trust store to chain against, and
		// answering true from a chain nobody built would be the more dangerous
		// direction. An expired certificate is the check a policy actually
		// writes this for.
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("Verify takes no arguments")
			}
			now := time.Now().UTC()
			return Bool(now.After(c.certificate.NotBefore) && now.Before(c.certificate.NotAfter)), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type responseHost struct {
	response *http.Response
}

func (r *responseHost) member(name string) (Value, error) {
	switch name {
	case "StatusCode":
		return Int(int64(r.response.StatusCode)), nil
	case "StatusReason":
		if r.response.Status != "" {
			return String(r.response.Status), nil
		}
		return String(http.StatusText(r.response.StatusCode)), nil
	case "Headers":
		return Object(&headerHost{header: r.response.Header}), nil
	case "Body":
		return Object(&bodyHost{read: func() (string, error) { return readResponseBody(r.response) }}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type lastErrorHost struct {
	err error
	// located is the failure's position, supplied by the policy engine. Nil
	// when the error came from somewhere that knows no position, in which case
	// every member but Message reads empty rather than guessing.
	located ErrorLocation
}

// ErrorLocation is where a failure happened, as the policy engine reports it.
//
// An interface rather than a struct because `internal/policy` imports this
// package: the engine supplies its own error and this reads it back, without
// the dependency running the other way.
type ErrorLocation interface {
	Element() string
	Section() string
	Scope() string
	Reason() string
}

func (e *lastErrorHost) member(name string) (Value, error) {
	switch name {
	case "Message":
		return String(e.err.Error()), nil
	case "Source":
		// Microsoft defines Source as "name of the element where the error
		// occurred", which is exactly this. An `Element` alias sat here too,
		// under a comment claiming Azure exposed both names. It does not.
		return String(locatedValue(e.located, ErrorLocation.Element)), nil
	case "Section":
		return String(locatedValue(e.located, ErrorLocation.Section)), nil
	case "Scope":
		return String(locatedValue(e.located, ErrorLocation.Scope)), nil
	case "Reason":
		return String(locatedValue(e.located, ErrorLocation.Reason)), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// locatedValue reads one field of a location that may not exist.
func locatedValue(location ErrorLocation, read func(ErrorLocation) string) string {
	if location == nil {
		return ""
	}
	return read(location)
}

type urlHost struct {
	request *http.Request
}

func (u *urlHost) String() string {
	if u.request.URL == nil {
		return ""
	}
	if u.request.URL.IsAbs() {
		return u.request.URL.String()
	}
	scheme := "http"
	if u.request.TLS != nil {
		scheme = "https"
	}
	host := u.request.Host
	if host == "" {
		host = u.request.URL.Host
	}
	return scheme + "://" + host + u.request.URL.RequestURI()
}

func (u *urlHost) member(name string) (Value, error) {
	url := u.request.URL
	if url == nil {
		return Null(), fmt.Errorf("unknown member %s", name)
	}
	switch name {
	case "Path":
		return String(url.Path), nil
	case "Host":
		host := u.request.Host
		if host == "" {
			host = url.Host
		}
		return String(host), nil
	case "Scheme":
		if url.Scheme != "" {
			return String(url.Scheme), nil
		}
		if u.request.TLS != nil {
			return String("https"), nil
		}
		return String("http"), nil
	case "Query":
		return String(url.RawQuery), nil
	case "QueryString":
		if url.RawQuery == "" {
			return String(""), nil
		}
		return String("?" + url.RawQuery), nil
	case "Port":
		return Int(u.port()), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func (u *urlHost) port() int64 {
	if url := u.request.URL; url != nil {
		if port := url.Port(); port != "" {
			n, _ := strconv.Atoi(port)
			return int64(n)
		}
	}
	host := u.request.Host
	if host == "" && u.request.URL != nil {
		host = u.request.URL.Host
	}
	if _, port, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(port); err == nil {
			return int64(n)
		}
	}
	if (u.request.URL != nil && u.request.URL.Scheme == "https") || u.request.TLS != nil {
		return 443
	}
	return 80
}

type headerHost struct {
	header http.Header
}

func (h *headerHost) member(name string) (Value, error) {
	switch name {
	case "Get":
		return Object(funcValue{fn: h.get}), nil
	case "GetValueOrDefault":
		return Object(funcValue{fn: h.getValueOrDefault}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func (h *headerHost) get(args []Value) (Value, error) {
	if len(args) != 1 || args[0].kind != KindString {
		return Null(), fmt.Errorf("Get requires a header name")
	}
	return String(h.header.Get(args[0].str)), nil
}

func (h *headerHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("header index requires a string")
	}
	return String(h.header.Get(key.str)), nil
}

func (h *headerHost) getValueOrDefault(args []Value) (Value, error) {
	if len(args) == 0 || len(args) > 2 || args[0].kind != KindString {
		return Null(), fmt.Errorf("GetValueOrDefault requires a header name")
	}
	value := h.header.Get(args[0].str)
	if value == "" && len(args) == 2 {
		return args[1], nil
	}
	return String(value), nil
}

// certificateMapHost is the service's client certificates, keyed by name. It is
// a dictionary of OBJECTS, which the text-only mapHost cannot carry.
type certificateMapHost struct {
	certificates map[string]*x509.Certificate
}

func (m *certificateMapHost) member(name string) (Value, error) {
	switch name {
	case "ContainsKey":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("ContainsKey requires a string")
			}
			_, ok := m.certificates[args[0].str]
			return Bool(ok), nil
		}}), nil
	case "Count":
		return Double(float64(len(m.certificates))), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func (m *certificateMapHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("certificate lookup requires a string")
	}
	certificate, ok := m.certificates[key.str]
	if !ok {
		return Null(), nil
	}
	return Object(&certificateHost{certificate: certificate}), nil
}

type mapHost struct {
	values map[string]string
	// objects are variables whose value is a credential rather than text.
	objects map[string]AuthorizationContext
}

func (m *mapHost) member(name string) (Value, error) {
	switch name {
	case "ContainsKey":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("ContainsKey requires a string")
			}
			if m.values == nil {
				return Bool(false), nil
			}
			_, ok := m.values[args[0].str]
			return Bool(ok), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func (m *mapHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("index requires a string")
	}
	// An object variable is checked FIRST: get-authorization-context stores a
	// credential, and the documented expression reads a member off it. Falling
	// through to the string map would answer null and make
	// `.AccessToken` fail on a variable that is genuinely present.
	if credential, ok := m.objects[key.str]; ok {
		return Object(&authorizationHost{context: credential}), nil
	}
	if m.values == nil {
		return Null(), nil
	}
	value, ok := m.values[key.str]
	if !ok {
		return Null(), nil
	}
	return String(value), nil
}

type bodyHost struct {
	read func() (string, error)
}

func (b *bodyHost) member(name string) (Value, error) {
	switch name {
	case "As":
		// `As` without a type argument is not a member Azure has: the only
		// legal spelling is `As<T>()`. Saying so is more useful than "unknown
		// member As".
		return Null(), fmt.Errorf("Body.As requires a type argument, as in As<string>()")
	case "AsFormUrlEncodedContent":
		return Object(funcValue{fn: b.asFormUrlEncodedContent}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// genericMember serves `Body.As<T>()`.
//
// The type argument decides what comes back, which is the whole point of the
// generic: `As<string>()` is the raw body and `As<JObject>()` is parsed JSON a
// policy can index into. A type this emulator cannot produce is REFUSED rather
// than silently downgraded to a string, because a policy indexing into what it
// believes is an object would otherwise fail somewhere far from the cause.
func (b *bodyHost) genericMember(name, typeArg string) (Value, error) {
	if name != "As" {
		return Null(), fmt.Errorf("%s is not a generic member", name)
	}
	switch typeArg {
	case "string", "String":
		return Object(funcValue{fn: b.asString}), nil
	case "JObject", "JToken", "JArray":
		return Object(funcValue{fn: b.asJSON}), nil
	default:
		return Null(), fmt.Errorf("Body.As<%s> is not supported; this emulator reads a body as string, JObject, JToken or JArray", typeArg)
	}
}

// asJSON parses the body into a value a policy can index into.
func (b *bodyHost) asJSON(args []Value) (Value, error) {
	if len(args) > 1 {
		return Null(), fmt.Errorf("As takes at most one argument")
	}
	text, err := b.read()
	if err != nil {
		return Null(), err
	}
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return Null(), fmt.Errorf("the body is not JSON: %w", err)
	}
	// jsonValue collapses an object or array to its JSON TEXT, which is right
	// for a GraphQL argument and wrong here: `As<JObject>()` exists so a policy
	// can index into the result.
	return jsonDocument(decoded)
}

// asFormUrlEncodedContent parses a form body into a dictionary of values.
//
// Azure returns IDictionary<string, IList<string>>: a field may legitimately
// repeat, and collapsing it to the first value would lose that. Each field is
// a collection here for the same reason.
func (b *bodyHost) asFormUrlEncodedContent(args []Value) (Value, error) {
	if len(args) > 1 {
		return Null(), fmt.Errorf("AsFormUrlEncodedContent takes at most one argument")
	}
	text, err := b.read()
	if err != nil {
		return Null(), err
	}
	form, err := url.ParseQuery(text)
	if err != nil {
		return Null(), fmt.Errorf("the body is not form-encoded: %w", err)
	}
	fields := map[string]Value{}
	for name, values := range form {
		items := make([]Value, 0, len(values))
		for _, value := range values {
			items = append(items, String(value))
		}
		fields[name] = Object(&listHost{items: items, what: "values"})
	}
	return Object(&formHost{fields: fields}), nil
}

// formHost is the parsed form body: a dictionary of field name to values.
type formHost struct {
	fields map[string]Value
}

func (f *formHost) member(name string) (Value, error) {
	switch name {
	case "Count":
		return Double(float64(len(f.fields))), nil
	case "ContainsKey":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("ContainsKey requires a string")
			}
			_, ok := f.fields[args[0].str]
			return Bool(ok), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func (f *formHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("a form body is indexed by field name")
	}
	value, ok := f.fields[key.str]
	if !ok {
		return Null(), nil
	}
	return value, nil
}

func (b *bodyHost) asString(args []Value) (Value, error) {
	if len(args) != 0 {
		return Null(), fmt.Errorf("AsString takes no arguments")
	}
	value, err := b.read()
	if err != nil {
		return Null(), err
	}
	return String(value), nil
}

func readRequestBody(request *http.Request) (string, error) {
	if request == nil {
		return "", nil
	}
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return "", err
		}
		defer body.Close()
		value, err := io.ReadAll(body)
		if err != nil {
			return "", err
		}
		return string(value), nil
	}
	if request.Body == nil {
		return "", nil
	}
	value, err := io.ReadAll(request.Body)
	if err != nil {
		return "", err
	}
	_ = request.Body.Close()
	request.Body = io.NopCloser(strings.NewReader(string(value)))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(string(value))), nil
	}
	request.ContentLength = int64(len(value))
	return string(value), nil
}

func readResponseBody(response *http.Response) (string, error) {
	if response == nil || response.Body == nil {
		return "", nil
	}
	value, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	_ = response.Body.Close()
	response.Body = io.NopCloser(strings.NewReader(string(value)))
	return string(value), nil
}

func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

// AuthorizationContext is what get-authorization-context stores: the credential
// APIM holds for a backend call.
//
// AccessToken is the only member a policy needs to attach the credential, and
// it is deliberately the only one carrying secret material. The rest describe
// WHICH credential was used, so a policy can branch on it without handling the
// token itself.
type AuthorizationContext struct {
	AccessToken string
	ClientID    string
	Scopes      string
	ExpiresIn   int64
}

type authorizationHost struct {
	context AuthorizationContext
}

func (h *authorizationHost) member(name string) (Value, error) {
	switch name {
	case "AccessToken":
		return String(h.context.AccessToken), nil
	case "ClientId":
		return String(h.context.ClientID), nil
	case "Scopes":
		return String(h.context.Scopes), nil
	case "ExpiresIn":
		return Int(h.context.ExpiresIn), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}
