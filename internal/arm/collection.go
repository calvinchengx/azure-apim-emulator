package arm

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func (h *Handler) handleCollectionRequest(w http.ResponseWriter, r *http.Request, rt route) bool {
	if r.Method != http.MethodGet {
		return false
	}
	response := httptest.NewRecorder()
	h.dispatch(response, r, rt)
	writeCollectionResponse(w, r, response)
	return true
}

func writeCollectionResponse(w http.ResponseWriter, r *http.Request, response *httptest.ResponseRecorder) {
	if response.Code < 200 || response.Code >= 300 {
		copyRecordedResponse(w, response)
		return
	}
	var document map[string]any
	if json.Unmarshal(response.Body.Bytes(), &document) != nil {
		copyRecordedResponse(w, response)
		return
	}
	values, ok := document["value"].([]any)
	if !ok {
		copyRecordedResponse(w, response)
		return
	}

	filter, err := parseFilter(r.URL.Query().Get("$filter"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.Error(), "$filter")
		return
	}
	filtered := make([]any, 0, len(values))
	for _, value := range values {
		resource, ok := value.(map[string]any)
		if !ok {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", "The collection cannot be filtered.", "$filter")
			return
		}
		matches, err := filter(resource)
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.Error(), "$filter")
			return
		}
		if matches {
			filtered = append(filtered, value)
		}
	}

	skip, err := collectionInteger(r.URL.Query(), "$skip", 0, math.MaxInt32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.Error(), "$skip")
		return
	}
	if skip < 0 {
		skip = 0
	}
	top, err := collectionInteger(r.URL.Query(), "$top", 1, math.MaxInt32)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.Error(), "$top")
		return
	}
	if skip > len(filtered) {
		skip = len(filtered)
	}
	end := len(filtered)
	if top >= 0 && top < end-skip {
		end = skip + top
	}
	document["value"] = filtered[skip:end]
	document["count"] = len(filtered)
	document["nextLink"] = ""
	if end < len(filtered) {
		next := *r.URL
		query := next.Query()
		query.Set("$skip", strconv.Itoa(end))
		next.RawQuery = query.Encode()
		document["nextLink"] = absolute(r, next.RequestURI())
	}
	copyHeaders(w.Header(), response.Header())
	w.Header().Del("Content-Length")
	writeJSON(w, response.Code, document)
}

func collectionInteger(query url.Values, name string, minimum, maximum int) (int, error) {
	value, present := query[name]
	if !present {
		return -1, nil
	}
	if len(value) != 1 {
		return 0, fmt.Errorf("%s must be specified once", name)
	}
	parsed, err := strconv.ParseInt(value[0], 10, 32)
	if err != nil || int(parsed) < minimum || int(parsed) > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d", name, minimum, maximum)
	}
	return int(parsed), nil
}

type filterPredicate func(map[string]any) (bool, error)
type filterOperand func(map[string]any) (any, error)

func parseFilter(source string) (filterPredicate, error) {
	if strings.TrimSpace(source) == "" {
		return func(map[string]any) (bool, error) { return true, nil }, nil
	}
	parser, err := newFilterParser(source)
	if err != nil {
		return nil, err
	}
	result, err := parser.parseOr()
	if err != nil {
		return nil, err
	}
	if parser.current.kind != filterEOF {
		return nil, fmt.Errorf("unexpected token %q", parser.current.text)
	}
	return result, nil
}

type filterTokenKind int

const (
	filterEOF filterTokenKind = iota
	filterIdentifier
	filterString
	filterNumber
	filterLeftParen
	filterRightParen
	filterComma
)

type filterToken struct {
	kind filterTokenKind
	text string
}

type filterParser struct {
	tokens  []filterToken
	index   int
	current filterToken
}

func newFilterParser(source string) (*filterParser, error) {
	tokens, err := lexFilter(source)
	if err != nil {
		return nil, err
	}
	return &filterParser{tokens: tokens, current: tokens[0]}, nil
}

func lexFilter(source string) ([]filterToken, error) {
	var tokens []filterToken
	for index := 0; index < len(source); {
		character := rune(source[index])
		if unicode.IsSpace(character) {
			index++
			continue
		}
		switch source[index] {
		case '(':
			tokens = append(tokens, filterToken{kind: filterLeftParen, text: "("})
			index++
		case ')':
			tokens = append(tokens, filterToken{kind: filterRightParen, text: ")"})
			index++
		case ',':
			tokens = append(tokens, filterToken{kind: filterComma, text: ","})
			index++
		case '\'':
			start := index
			index++
			var value strings.Builder
			closed := false
			for index < len(source) {
				if source[index] != '\'' {
					value.WriteByte(source[index])
					index++
					continue
				}
				if index+1 < len(source) && source[index+1] == '\'' {
					value.WriteByte('\'')
					index += 2
					continue
				}
				index++
				closed = true
				break
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string at offset %d", start)
			}
			tokens = append(tokens, filterToken{kind: filterString, text: value.String()})
		default:
			start := index
			for index < len(source) && !unicode.IsSpace(rune(source[index])) && !strings.ContainsRune("(),", rune(source[index])) {
				index++
			}
			text := source[start:index]
			kind := filterIdentifier
			if _, err := strconv.ParseFloat(text, 64); err == nil {
				kind = filterNumber
			}
			tokens = append(tokens, filterToken{kind: kind, text: text})
		}
	}
	tokens = append(tokens, filterToken{kind: filterEOF})
	return tokens, nil
}

func (p *filterParser) advance() {
	p.index++
	p.current = p.tokens[p.index]
}

func (p *filterParser) keyword(value string) bool {
	return p.current.kind == filterIdentifier && strings.EqualFold(p.current.text, value)
}

func (p *filterParser) parseOr() (filterPredicate, error) {
	left, err := p.parseAnd()
	for err == nil && p.keyword("or") {
		p.advance()
		var right filterPredicate
		right, err = p.parseAnd()
		if err == nil {
			previous := left
			left = func(resource map[string]any) (bool, error) {
				matched, err := previous(resource)
				if err != nil || matched {
					return matched, err
				}
				return right(resource)
			}
		}
	}
	return left, err
}

func (p *filterParser) parseAnd() (filterPredicate, error) {
	left, err := p.parsePrimary()
	for err == nil && p.keyword("and") {
		p.advance()
		var right filterPredicate
		right, err = p.parsePrimary()
		if err == nil {
			previous := left
			left = func(resource map[string]any) (bool, error) {
				matched, err := previous(resource)
				if err != nil || !matched {
					return matched, err
				}
				return right(resource)
			}
		}
	}
	return left, err
}

func (p *filterParser) parsePrimary() (filterPredicate, error) {
	if p.current.kind == filterLeftParen {
		p.advance()
		result, err := p.parseOr()
		if err != nil || p.current.kind != filterRightParen {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.advance()
		return result, nil
	}
	if p.current.kind != filterIdentifier {
		return nil, fmt.Errorf("expected a field or function, got %q", p.current.text)
	}
	name := p.current.text
	p.advance()
	if p.current.kind == filterLeftParen {
		return p.parseFunction(name)
	}
	operator := strings.ToLower(p.current.text)
	if p.current.kind != filterIdentifier || !oneOf(operator, "eq", "ne", "gt", "ge", "lt", "le") {
		return nil, fmt.Errorf("expected a comparison operator after %s", name)
	}
	p.advance()
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	left := fieldOperand(name)
	return func(resource map[string]any) (bool, error) {
		leftValue, err := left(resource)
		if err != nil {
			return false, err
		}
		rightValue, err := right(resource)
		if err != nil {
			return false, err
		}
		return compareFilterValues(leftValue, rightValue, operator)
	}, nil
}

func (p *filterParser) parseFunction(name string) (filterPredicate, error) {
	name = strings.ToLower(name)
	if !oneOf(name, "contains", "startswith", "endswith", "substringof") {
		return nil, fmt.Errorf("unsupported filter function %q", name)
	}
	p.advance()
	first, err := p.parseOperand()
	if err != nil || p.current.kind != filterComma {
		return nil, fmt.Errorf("%s requires two arguments", name)
	}
	p.advance()
	second, err := p.parseOperand()
	if err != nil || p.current.kind != filterRightParen {
		return nil, fmt.Errorf("%s requires two arguments", name)
	}
	p.advance()
	return func(resource map[string]any) (bool, error) {
		left, err := first(resource)
		if err != nil {
			return false, err
		}
		right, err := second(resource)
		if err != nil {
			return false, err
		}
		leftString, leftOK := left.(string)
		rightString, rightOK := right.(string)
		if !leftOK || !rightOK {
			return false, fmt.Errorf("%s arguments must be strings", name)
		}
		switch name {
		case "contains":
			return strings.Contains(leftString, rightString), nil
		case "startswith":
			return strings.HasPrefix(leftString, rightString), nil
		case "endswith":
			return strings.HasSuffix(leftString, rightString), nil
		default:
			return strings.Contains(rightString, leftString), nil
		}
	}, nil
}

func (p *filterParser) parseOperand() (filterOperand, error) {
	token := p.current
	switch token.kind {
	case filterString:
		p.advance()
		return literalOperand(token.text), nil
	case filterNumber:
		p.advance()
		value, _ := strconv.ParseFloat(token.text, 64)
		return literalOperand(value), nil
	case filterIdentifier:
		p.advance()
		switch strings.ToLower(token.text) {
		case "true":
			return literalOperand(true), nil
		case "false":
			return literalOperand(false), nil
		case "null":
			return literalOperand(nil), nil
		default:
			return fieldOperand(token.text), nil
		}
	default:
		return nil, fmt.Errorf("expected a filter value, got %q", token.text)
	}
}

func literalOperand(value any) filterOperand {
	return func(map[string]any) (any, error) { return value, nil }
}

func fieldOperand(name string) filterOperand {
	return func(resource map[string]any) (any, error) {
		current := any(resource)
		parts := strings.Split(name, "/")
		for index, part := range parts {
			object, ok := current.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("filter field %q does not exist", name)
			}
			value, found := caseInsensitiveValue(object, part)
			if !found && index == 0 {
				if properties, ok := object["properties"].(map[string]any); ok {
					value, found = caseInsensitiveValue(properties, part)
				}
			}
			if !found {
				return nil, fmt.Errorf("filter field %q does not exist", name)
			}
			current = value
		}
		return current, nil
	}
}

func caseInsensitiveValue(object map[string]any, name string) (any, bool) {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func compareFilterValues(left, right any, operator string) (bool, error) {
	if left == nil || right == nil {
		equal := left == nil && right == nil
		if operator == "eq" {
			return equal, nil
		}
		if operator == "ne" {
			return !equal, nil
		}
		return false, fmt.Errorf("operator %s cannot compare null", operator)
	}
	var comparison int
	switch leftValue := left.(type) {
	case string:
		rightValue, ok := right.(string)
		if !ok {
			return false, fmt.Errorf("filter values have incompatible types")
		}
		comparison = strings.Compare(leftValue, rightValue)
	case float64:
		rightValue, ok := right.(float64)
		if !ok {
			return false, fmt.Errorf("filter values have incompatible types")
		}
		if leftValue < rightValue {
			comparison = -1
		} else if leftValue > rightValue {
			comparison = 1
		}
	case bool:
		rightValue, ok := right.(bool)
		if !ok || !oneOf(operator, "eq", "ne") {
			return false, fmt.Errorf("boolean filters support only eq and ne")
		}
		if leftValue != rightValue {
			comparison = 1
		}
	default:
		return false, fmt.Errorf("filter field has unsupported type %T", left)
	}
	switch operator {
	case "eq":
		return comparison == 0, nil
	case "ne":
		return comparison != 0, nil
	case "gt":
		return comparison > 0, nil
	case "ge":
		return comparison >= 0, nil
	case "lt":
		return comparison < 0, nil
	default:
		return comparison <= 0, nil
	}
}

func oneOf(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}
