package expression

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// NamedContext is Id/Name for Product, Subscription, and User.
type NamedContext struct {
	Id   string
	Name string
}

// ApiContext is the documented scalar API identity.
type ApiContext struct {
	Id   string
	Name string
	Path string
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
}

// Context is the APIM `context` binding for one evaluation.
type Context struct {
	Request      *http.Request
	Response     *http.Response
	Variables    map[string]string
	LastError    error
	Api          *ApiContext
	Operation    *OperationContext
	Product      *NamedContext
	Subscription *NamedContext
	User         *NamedContext
	Deployment   *DeploymentContext
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
		return Object(&requestHost{request: c.ctx.Request}), nil
	case "Response":
		if c.ctx.Response == nil {
			return Null(), nil
		}
		return Object(&responseHost{response: c.ctx.Response}), nil
	case "Variables":
		return Object(&mapHost{values: c.ctx.Variables}), nil
	case "LastError":
		if c.ctx.LastError == nil {
			return Null(), nil
		}
		return Object(&lastErrorHost{err: c.ctx.LastError}), nil
	case "Api":
		if c.ctx.Api == nil {
			return Null(), nil
		}
		return Object(&apiHost{id: c.ctx.Api.Id, name: c.ctx.Api.Name, path: c.ctx.Api.Path}), nil
	case "Operation":
		if c.ctx.Operation == nil {
			return Null(), nil
		}
		return Object(&operationHost{id: c.ctx.Operation.Id, name: c.ctx.Operation.Name, method: c.ctx.Operation.Method, urlTemplate: c.ctx.Operation.UrlTemplate}), nil
	case "Product":
		return namedObject(c.ctx.Product), nil
	case "Subscription":
		return namedObject(c.ctx.Subscription), nil
	case "User":
		return namedObject(c.ctx.User), nil
	case "Deployment":
		if c.ctx.Deployment == nil {
			return Null(), nil
		}
		return Object(&deploymentHost{serviceName: c.ctx.Deployment.ServiceName, region: c.ctx.Deployment.Region}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

func namedObject(value *NamedContext) Value {
	if value == nil {
		return Null()
	}
	return Object(&namedHost{id: value.Id, name: value.Name})
}

type namedHost struct {
	id   string
	name string
}

func (h *namedHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.id), nil
	case "Name":
		return String(h.name), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type apiHost struct {
	id   string
	name string
	path string
}

func (h *apiHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(h.id), nil
	case "Name":
		return String(h.name), nil
	case "Path":
		return String(h.path), nil
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
	serviceName string
	region      string
}

func (h *deploymentHost) member(name string) (Value, error) {
	switch name {
	case "ServiceName":
		return String(h.serviceName), nil
	case "Region":
		return String(h.region), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type requestHost struct {
	request *http.Request
}

func (r *requestHost) member(name string) (Value, error) {
	switch name {
	case "Method":
		return String(r.request.Method), nil
	case "Url", "URL":
		return Object(&urlHost{request: r.request}), nil
	case "Headers":
		return Object(&headerHost{header: r.request.Header}), nil
	case "IpAddress":
		return String(clientIP(r.request.RemoteAddr)), nil
	case "Body":
		return Object(&bodyHost{read: func() (string, error) { return readRequestBody(r.request) }}), nil
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
}

func (e *lastErrorHost) member(name string) (Value, error) {
	switch name {
	case "Message":
		return String(e.err.Error()), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
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

type mapHost struct {
	values map[string]string
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
	case "AsString":
		return Object(funcValue{fn: b.asString}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
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
