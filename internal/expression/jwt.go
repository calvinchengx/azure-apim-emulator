package expression

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JWT and HTTP Basic credentials, which Microsoft exposes as extension methods
// on `string` rather than as members of the context graph.
//
// Both are documented to return NULL for input they cannot parse, not to fail.
// That is the contract a policy is written against: `AsJwt() != null` is how a
// policy asks whether a header held a token, so raising here would break the
// question rather than answer it.

// DecodeJWT splits a token into its header and payload claims. The signature is
// NOT verified: this reads a token, and `validate-jwt` is what checks one.
func DecodeJWT(token string) (header, payload map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("invalid jwt")
	}
	// The PAYLOAD decides whether this is a token: it carries the claims every
	// caller wants. The header is best-effort, and an unreadable one leaves
	// Algorithm and Type empty rather than rejecting the token, because
	// `validate-jwt` has always read the payload alone and tightening that here
	// would change which tokens the gateway accepts.
	header, _ = decodeJWTSegment(parts[0])
	if payload, err = decodeJWTSegment(parts[1]); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

// decodeJWTSegment accepts padded and unpadded base64url. Tokens in the wild
// carry both, and rejecting either would refuse valid tokens.
func decodeJWTSegment(segment string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(segment); err != nil {
			return nil, err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// asJwt is the `AsJwt()` extension method. Null rather than an error for input
// that is not a token, which is what Microsoft documents.
func asJwt(token string) Value {
	header, payload, err := DecodeJWT(token)
	if err != nil {
		return Null()
	}
	return Object(&jwtHost{header: header, payload: payload})
}

type jwtHost struct {
	header  map[string]any
	payload map[string]any
}

func (j *jwtHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(jwtString(j.payload, "jti")), nil
	case "Issuer":
		return String(jwtString(j.payload, "iss")), nil
	case "Subject":
		return String(jwtString(j.payload, "sub")), nil
	// Algorithm and Type come from the HEADER. Reading them off the payload
	// would answer empty for every real token.
	case "Algorithm":
		return String(jwtString(j.header, "alg")), nil
	case "Type":
		return String(jwtString(j.header, "typ")), nil
	case "Audiences":
		// `aud` is a string OR an array of them, and both spellings are valid
		// in a token, so both read as a collection here.
		return jwtAudiences(j.payload["aud"]), nil
	case "Claims":
		return Object(&claimsHost{payload: j.payload}), nil
	// The three times are `DateTime?`, so an absent one is NULL rather than the
	// unix epoch, which a policy comparing against "now" would read as long past.
	case "ExpirationTime":
		return jwtTime(j.payload, "exp"), nil
	case "NotBefore":
		return jwtTime(j.payload, "nbf"), nil
	case "IssuedAt":
		return jwtTime(j.payload, "iat"), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a jwt", name)
	}
}

func jwtString(claims map[string]any, name string) string {
	if value, ok := claims[name].(string); ok {
		return value
	}
	return ""
}

func jwtTime(claims map[string]any, name string) Value {
	seconds, ok := claims[name].(float64)
	if !ok {
		return Null()
	}
	return String(time.Unix(int64(seconds), 0).UTC().Format(time.RFC3339))
}

func jwtAudiences(value any) Value {
	items := []Value{}
	switch typed := value.(type) {
	case string:
		items = append(items, String(typed))
	case []any:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				items = append(items, String(text))
			}
		}
	}
	return Object(&listHost{items: items, what: "audiences"})
}

// claimsHost is `Jwt.Claims`, typed by Microsoft as a dictionary of name to
// VALUES: a claim may legitimately repeat, and `Claims["roles"][0]` is how a
// policy reads one.
type claimsHost struct {
	payload map[string]any
}

func (c *claimsHost) member(name string) (Value, error) {
	switch name {
	case "GetValueOrDefault":
		return Object(funcValue{fn: c.getValueOrDefault}), nil
	case "ContainsKey":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("ContainsKey requires a claim name")
			}
			_, ok := c.payload[args[0].str]
			return Bool(ok), nil
		}}), nil
	case "Count":
		return Double(float64(len(c.payload))), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on jwt claims", name)
	}
}

func (c *claimsHost) index(key Value) (Value, error) {
	if key.kind != KindString {
		return Null(), fmt.Errorf("claims are indexed by claim name")
	}
	values, ok := claimValues(c.payload, key.str)
	if !ok {
		return Null(), nil
	}
	items := make([]Value, 0, len(values))
	for _, value := range values {
		items = append(items, String(value))
	}
	return Object(&listHost{items: items, what: "claim values"}), nil
}

func (c *claimsHost) getValueOrDefault(args []Value) (Value, error) {
	if len(args) == 0 || len(args) > 2 || args[0].kind != KindString {
		return Null(), fmt.Errorf("GetValueOrDefault requires a claim name")
	}
	if values, ok := claimValues(c.payload, args[0].str); ok && len(values) > 0 {
		return String(values[0]), nil
	}
	if len(args) == 2 {
		return args[1], nil
	}
	return String(""), nil
}

// claimValues renders one claim as the string values Microsoft's type promises.
// A number or boolean claim renders the way the rest of this evaluator renders
// it, so `exp` reads the same here as it does anywhere else.
func claimValues(payload map[string]any, name string) ([]string, bool) {
	raw, ok := payload[name]
	if !ok {
		return nil, false
	}
	switch typed := raw.(type) {
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			converted, err := jsonValue(item)
			if err != nil {
				return nil, false
			}
			values = append(values, converted.String())
		}
		return values, true
	default:
		converted, err := jsonValue(typed)
		if err != nil {
			return nil, false
		}
		return []string{converted.String()}, true
	}
}

// asBasic is the `AsBasic()` extension method. It accepts the raw header value,
// with or without the `Basic ` scheme, and answers null for anything that is not
// a `user:password` pair, which is what Microsoft documents.
func asBasic(header string) Value {
	encoded := strings.TrimSpace(header)
	if scheme, rest, ok := strings.Cut(encoded, " "); ok && strings.EqualFold(scheme, "Basic") {
		encoded = strings.TrimSpace(rest)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Null()
	}
	username, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return Null()
	}
	return Object(&basicCredentialsHost{username: username, password: password})
}

type basicCredentialsHost struct {
	username, password string
}

func (b *basicCredentialsHost) member(name string) (Value, error) {
	switch name {
	case "Username":
		return String(b.username), nil
	case "Password":
		return String(b.password), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on basic credentials", name)
	}
}
