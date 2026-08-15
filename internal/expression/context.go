package expression

import (
	"fmt"
	"net"
	"net/http"
)

// Context is the APIM `context` binding for one evaluation.
type Context struct {
	Request   *http.Request
	Response  *http.Response
	Variables map[string]string
	LastError error
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
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type lastErrorHost struct {
	err error
}

func (e *lastErrorHost) member(name string) (Value, error) {
	if name != "Message" {
		return Null(), fmt.Errorf("unknown member %s", name)
	}
	return String(e.err.Error()), nil
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
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

type headerHost struct {
	header http.Header
}

func (h *headerHost) member(name string) (Value, error) {
	if name != "GetValueOrDefault" {
		return Null(), fmt.Errorf("unknown member %s", name)
	}
	return Object(funcValue{fn: h.getValueOrDefault}), nil
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
	if name != "ContainsKey" {
		return Null(), fmt.Errorf("unknown member %s", name)
	}
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

func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
