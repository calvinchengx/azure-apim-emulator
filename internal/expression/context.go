package expression

import (
	"fmt"
	"net"
	"net/http"
)

// RequestEnv binds the APIM `context` identifier from an HTTP request and
// policy variables. A nil request still binds `context` so literal expressions
// evaluate; member access on the missing request fails at the member.
func RequestEnv(request *http.Request, variables map[string]string) *Env {
	return &Env{Bindings: map[string]Value{
		"context": Object(&contextHost{request: request, variables: variables}),
	}}
}

type contextHost struct {
	request   *http.Request
	variables map[string]string
}

func (c *contextHost) member(name string) (Value, error) {
	switch name {
	case "Request":
		if c.request == nil {
			return Null(), nil
		}
		return Object(&requestHost{request: c.request}), nil
	case "Variables":
		return Object(&mapHost{values: c.variables}), nil
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

type urlHost struct {
	request *http.Request
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
