package arm

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
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
	h.writeCollectionResponse(w, r, response, rt)
	return true
}

func writeCollectionResponse(w http.ResponseWriter, r *http.Request, response *httptest.ResponseRecorder, rt route) {
	writeCollectionResponseWithHandler(nil, w, r, response, rt)
}

func (h *Handler) writeCollectionResponse(w http.ResponseWriter, r *http.Request, response *httptest.ResponseRecorder, rt route) {
	writeCollectionResponseWithHandler(h, w, r, response, rt)
}

func writeCollectionResponseWithHandler(h *Handler, w http.ResponseWriter, r *http.Request, response *httptest.ResponseRecorder, rt route) {
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
	if name := unsupportedCollectionOption(r.URL.Query(), rt); name != "" {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", fmt.Sprintf("The query option %s is not supported for this operation.", name), name)
		return
	}
	if err := validateCollectionSelectors(r.URL.Query(), rt); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.message, err.target)
		return
	}

	filter, err := parseFilterForRoute(r.URL.Query().Get("$filter"), rt)
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
	if h != nil {
		filtered, err = h.applyCollectionSelectors(filtered, r.URL.Query(), rt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.Error(), "$filter")
			return
		}
	}
	order, err := parseCollectionOrder(r.URL.Query(), rt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "InvalidQueryParameterValue", err.Error(), "$orderby")
		return
	}
	if order != 0 {
		sort.SliceStable(filtered, func(left, right int) bool {
			leftName, _ := caseInsensitiveValue(filtered[left].(map[string]any), "name")
			rightName, _ := caseInsensitiveValue(filtered[right].(map[string]any), "name")
			comparison := strings.Compare(fmt.Sprint(leftName), fmt.Sprint(rightName))
			return comparison*order < 0
		})
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
	// Not every collection in this provider carries a count. Microsoft's
	// `TenantSettingsCollection` has `value` and `nextLink` only, where its
	// `AccessInformationCollection` neighbour has all three, and Azure's own
	// examples agree with both. An extra field is invisible to a generated
	// client, which is exactly why it would never be found later.
	if collectionsWithoutCount[strings.ToLower(collectionFilterKey(rt.Tail))] {
		delete(document, "count")
	}
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

type collectionSelectorError struct {
	target  string
	message string
}

// collectionsWithoutCount are the list operations whose response model has no
// `count`, keyed the same way as collectionFilterKey but lowercased.
var collectionsWithoutCount = map[string]bool{"settings": true}

var collectionSelectors = map[string]map[string]bool{
	"apis":            {"tags": true, "expandApiVersionSet": true},
	"apis/operations": {"tags": true},
	"certificates":    {"isKeyVaultRefreshFailed": true},
	"namedValues":     {"isKeyVaultRefreshFailed": true},
	"products":        {"expandGroups": true, "tags": true},
	"tags":            {"scope": true},
	"users":           {"expandGroups": true},
}

func validateCollectionSelectors(query url.Values, rt route) *collectionSelectorError {
	allowed := collectionSelectors[collectionFilterKey(rt.Tail)]
	for name := range query {
		if !oneOf(name, "tags", "scope", "expandGroups", "expandApiVersionSet", "isKeyVaultRefreshFailed") {
			continue
		}
		if !allowed[name] {
			return &collectionSelectorError{target: name, message: fmt.Sprintf("The query parameter %s is not supported for this operation.", name)}
		}
		if name == "scope" && (len(query[name]) != 1 || !oneOf(strings.ToLower(query.Get(name)), "apis", "operations", "products")) {
			return &collectionSelectorError{target: name, message: "scope must be one of apis, operations, or products."}
		}
		if oneOf(name, "expandGroups", "expandApiVersionSet", "isKeyVaultRefreshFailed") {
			values := query[name]
			if len(values) != 1 || !oneOf(strings.ToLower(values[0]), "true", "false") {
				return &collectionSelectorError{target: name, message: fmt.Sprintf("%s must be a boolean.", name)}
			}
		}
	}
	return nil
}

func (h *Handler) applyCollectionSelectors(values []any, query url.Values, rt route) ([]any, error) {
	key := collectionFilterKey(rt.Tail)
	if key == "products" && query.Get("tags") != "" {
		var err error
		values, err = h.filterProductsByTag(values, query.Get("tags"))
		if err != nil {
			return nil, err
		}
	}
	if key == "tags" && query.Get("scope") != "" {
		serviceID := rt.ServiceName
		if rt.SubscriptionID != "" || rt.ResourceGroup != "" {
			serviceID = "/subscriptions/" + rt.SubscriptionID + "/resourceGroups/" + rt.ResourceGroup + "/providers/Microsoft.ApiManagement/service/" + rt.ServiceName
		}
		tags, err := h.Store.ListTagsByScope(serviceID, query.Get("scope"))
		if err != nil {
			return nil, err
		}
		filtered := make([]any, 0, len(tags))
		for _, tag := range tags {
			filtered = append(filtered, tagWire(tag))
		}
		values = filtered
	}
	if key == "apis" && query.Get("expandApiVersionSet") == "true" {
		for _, value := range values {
			resource, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("the collection cannot be expanded")
			}
			api, err := h.Store.GetAPI(resourceID(resource))
			if err != nil {
				return nil, err
			}
			if api.VersionSetID != "" {
				versionSet, err := h.Store.GetAPIVersionSet(api.VersionSetID)
				if err == nil {
					properties := resourceProperties(resource)
					properties["apiVersionSet"] = apiVersionSetWire(versionSet)
				}
			}
		}
	}
	if key == "apis" && query.Get("tags") != "" {
		if err := h.expandResourceTags(values); err != nil {
			return nil, err
		}
	}
	if key == "apis/operations" && query.Get("tags") != "" {
		if err := h.expandResourceTags(values); err != nil {
			return nil, err
		}
	}
	if key == "products" && query.Get("expandGroups") == "true" {
		if err := h.expandProductGroups(values); err != nil {
			return nil, err
		}
	}
	if key == "users" && query.Get("expandGroups") == "true" {
		if err := h.expandUserGroups(values); err != nil {
			return nil, err
		}
	}
	if (key == "namedValues" || key == "certificates") && query.Get("isKeyVaultRefreshFailed") == "true" {
		for _, value := range values {
			resource, ok := value.(map[string]any)
			if !ok {
				return nil, errors.New("the collection cannot project Key Vault refresh state")
			}
			properties := resourceProperties(resource)
			if _, present := properties["isKeyVaultRefreshFailed"]; !present {
				properties["isKeyVaultRefreshFailed"] = keyVaultRefreshFailed(properties)
			}
		}
	}
	return values, nil
}

func keyVaultRefreshFailed(properties map[string]any) bool {
	keyVault, _ := properties["keyVault"].(map[string]any)
	status, _ := keyVault["lastStatus"].(map[string]any)
	code, _ := status["code"].(string)
	return code != "" && !strings.EqualFold(code, "Success")
}

func (h *Handler) filterProductsByTag(values []any, want string) ([]any, error) {
	filtered := make([]any, 0, len(values))
	for _, value := range values {
		resource, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("the collection cannot be filtered by tags")
		}
		id, _ := resource["id"].(string)
		tags, err := h.Store.ListResourceTags(id)
		if err != nil {
			return nil, err
		}
		for _, tag := range tags {
			if strings.EqualFold(tag.Name, want) {
				filtered = append(filtered, value)
				break
			}
		}
	}
	return filtered, nil
}

func resourceID(resource map[string]any) string {
	id, _ := resource["id"].(string)
	return id
}

func resourceProperties(resource map[string]any) map[string]any {
	properties, ok := resource["properties"].(map[string]any)
	if !ok {
		properties = map[string]any{}
		resource["properties"] = properties
	}
	return properties
}

func (h *Handler) expandResourceTags(values []any) error {
	for _, value := range values {
		resource, ok := value.(map[string]any)
		if !ok {
			return errors.New("the collection cannot be expanded")
		}
		tags, err := h.Store.ListResourceTags(resourceID(resource))
		if err != nil {
			return err
		}
		wire := make([]any, 0, len(tags))
		for _, tag := range tags {
			wire = append(wire, tagWire(tag))
		}
		resourceProperties(resource)["tags"] = wire
	}
	return nil
}

func (h *Handler) expandProductGroups(values []any) error {
	for _, value := range values {
		resource, ok := value.(map[string]any)
		if !ok {
			return errors.New("the collection cannot be expanded")
		}
		groups, err := h.Store.ListProductGroups(resourceID(resource))
		if err != nil {
			return err
		}
		wire := make([]any, 0, len(groups))
		for _, group := range groups {
			wire = append(wire, groupWire(group))
		}
		resourceProperties(resource)["groups"] = wire
	}
	return nil
}

func (h *Handler) expandUserGroups(values []any) error {
	for _, value := range values {
		resource, ok := value.(map[string]any)
		if !ok {
			return errors.New("the collection cannot be expanded")
		}
		groups, err := h.Store.ListUserGroups(resourceID(resource))
		if err != nil {
			return err
		}
		wire := make([]any, 0, len(groups))
		for _, group := range groups {
			wire = append(wire, groupWire(group))
		}
		resourceProperties(resource)["groups"] = wire
	}
	return nil
}

func unsupportedCollectionOption(query url.Values, rt route) string {
	for name := range query {
		if !strings.HasPrefix(name, "$") {
			continue
		}
		if len(rt.Tail) == 0 {
			return name
		}
		if oneOf(name, "$filter", "$top", "$skip") {
			continue
		}
		if name == "$orderby" && policyFragmentCollection(rt) {
			continue
		}
		return name
	}
	return ""
}

func parseCollectionOrder(query url.Values, rt route) (int, error) {
	values, present := query["$orderby"]
	if !present {
		return 0, nil
	}
	if !policyFragmentCollection(rt) || len(values) != 1 {
		return 0, fmt.Errorf("$orderby must be specified once on a supported operation")
	}
	parts := strings.Fields(values[0])
	if len(parts) == 0 || len(parts) > 2 || !strings.EqualFold(parts[0], "name") {
		return 0, fmt.Errorf("$orderby supports only the name field")
	}
	if len(parts) == 1 || strings.EqualFold(parts[1], "asc") {
		return 1, nil
	}
	if strings.EqualFold(parts[1], "desc") {
		return -1, nil
	}
	return 0, fmt.Errorf("$orderby direction must be asc or desc")
}

func policyFragmentCollection(rt route) bool {
	return rt.ServiceName != "" && len(rt.Tail) == 1 && equal(rt.Tail[0], "policyFragments")
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

type filterOperand struct {
	evaluate filterOperandEvaluator
	field    string
}

type filterOperandEvaluator func(map[string]any) (any, error)

type filterFieldRule struct {
	operators []string
	functions []string
}

type filterContract map[string]filterFieldRule

var fullFilterRule = filterFieldRule{
	operators: []string{"eq", "ne", "gt", "ge", "lt", "le"},
	functions: []string{"contains", "startswith", "endswith", "substringof"},
}

var collectionFilterContracts = map[string]filterContract{
	"apis":                   makeFilterContract([]string{"name", "displayName", "description", "serviceUrl", "path"}, map[string]filterFieldRule{"isCurrent": comparisonRule("eq", "ne")}),
	"apis/diagnostics":       makeFilterContract([]string{"name"}, nil),
	"apis/operations":        makeFilterContract([]string{"name", "displayName", "method", "description", "urlTemplate"}, nil),
	"apis/releases":          makeFilterContract([]string{"notes"}, nil),
	"apis/revisions":         makeFilterContract([]string{"apiRevision"}, nil),
	"apis/schemas":           makeFilterContract([]string{"contentType"}, nil),
	"apis/tags":              makeFilterContract([]string{"name", "displayName"}, nil),
	"apis/operations/tags":   makeFilterContract([]string{"name", "displayName"}, nil),
	"apiVersionSets":         {},
	"backends":               makeFilterContract([]string{"name", "title", "url"}, nil),
	"caches":                 makeFilterContract([]string{"name", "description", "region"}, nil),
	"identityProviders":      {},
	"openidConnectProviders": makeFilterContract([]string{"name", "displayName"}, nil),
	"authorizationServers":   makeFilterContract([]string{"name", "displayName"}, nil),
	"documentations":         makeFilterContract(nil, map[string]filterFieldRule{"name": {operators: []string{"eq"}, functions: []string{"contains"}}}),
	"certificates":           makeFilterContract([]string{"name", "subject", "thumbprint"}, map[string]filterFieldRule{"expirationDate": comparisonRule("eq", "ne", "gt", "ge", "lt", "le")}),
	"diagnostics":            makeFilterContract([]string{"name"}, nil),
	"groups":                 makeFilterContract([]string{"name", "displayName", "description"}, map[string]filterFieldRule{"externalId": comparisonRule("eq")}),
	"groups/users":           makeFilterContract([]string{"name", "firstName", "lastName", "email", "note"}, map[string]filterFieldRule{"registrationDate": comparisonRule("eq", "ne", "gt", "ge", "lt", "le")}),
	"loggers":                makeFilterContract([]string{"name", "description", "resourceId"}, map[string]filterFieldRule{"loggerType": comparisonRule("eq")}),
	"namedValues":            makeFilterContract([]string{"displayName"}, map[string]filterFieldRule{"tags": {operators: []string{"eq", "ne", "gt", "ge", "lt", "le"}, functions: []string{"contains", "startswith", "endswith", "substringof", "any", "all"}}}),
	"policyFragments":        makeFilterContract([]string{"name", "description", "value"}, nil),
	"products":               makeFilterContract([]string{"name", "displayName", "description", "terms"}, map[string]filterFieldRule{"state": comparisonRule("eq")}),
	"products/apis":          makeFilterContract([]string{"name", "displayName", "description", "serviceUrl", "path"}, nil),
	"products/groups":        makeFilterContract(nil, map[string]filterFieldRule{"name": comparisonRule("eq", "ne", "gt", "ge", "lt", "le"), "displayName": comparisonRule("eq", "ne"), "description": comparisonRule("eq", "ne")}),
	"products/tags":          makeFilterContract([]string{"name", "displayName"}, nil),
	"subscriptions":          makeFilterContract([]string{"name", "displayName", "stateComment", "ownerId", "scope", "userId", "productId"}, map[string]filterFieldRule{"state": comparisonRule("eq")}),
	"tags":                   makeFilterContract([]string{"name", "displayName"}, nil),
	"users":                  makeFilterContract([]string{"name", "firstName", "lastName", "email", "note"}, map[string]filterFieldRule{"state": comparisonRule("eq"), "registrationDate": comparisonRule("eq", "ne", "gt", "ge", "lt", "le")}),
	"users/groups":           makeFilterContract([]string{"name", "displayName", "description"}, nil),
}

func comparisonRule(operators ...string) filterFieldRule {
	return filterFieldRule{operators: operators}
}

func makeFilterContract(fields []string, restricted map[string]filterFieldRule) filterContract {
	contract := filterContract{}
	for _, field := range fields {
		contract[strings.ToLower(field)] = fullFilterRule
	}
	for field, rule := range restricted {
		contract[strings.ToLower(field)] = rule
	}
	return contract
}

func parseFilterForRoute(source string, rt route) (filterPredicate, error) {
	key := collectionFilterKey(rt.Tail)
	contract, audited := collectionFilterContracts[key]
	if !audited {
		return parseFilter(source)
	}
	return parseFilterWithContract(source, contract)
}

func collectionFilterKey(tail []string) string {
	if len(tail) == 1 {
		return tail[0]
	}
	if len(tail) == 3 {
		return tail[0] + "/" + tail[2]
	}
	if len(tail) == 5 {
		return tail[0] + "/" + tail[2] + "/" + tail[4]
	}
	return ""
}

func parseFilter(source string) (filterPredicate, error) {
	return parseFilterWithContract(source, nil)
}

func parseFilterWithContract(source string, contract filterContract) (filterPredicate, error) {
	if strings.TrimSpace(source) == "" {
		return func(map[string]any) (bool, error) { return true, nil }, nil
	}
	parser, err := newFilterParser(source)
	if err != nil {
		return nil, err
	}
	parser.contract = contract
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
	filterColon
)

type filterToken struct {
	kind filterTokenKind
	text string
}

type filterParser struct {
	tokens   []filterToken
	index    int
	current  filterToken
	contract filterContract
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
		case ':':
			tokens = append(tokens, filterToken{kind: filterColon, text: ":"})
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
			for index < len(source) && !unicode.IsSpace(rune(source[index])) && !strings.ContainsRune("(),:", rune(source[index])) {
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
	if p.contract != nil && right.field != "" {
		return nil, fmt.Errorf("filter comparisons require a literal right operand")
	}
	if err := p.validateField(name, operator, ""); err != nil {
		return nil, err
	}
	left := fieldOperand(name)
	return func(resource map[string]any) (bool, error) {
		leftValue, err := left.evaluate(resource)
		if err != nil {
			return false, err
		}
		rightValue, err := right.evaluate(resource)
		if err != nil {
			return false, err
		}
		return compareFilterValues(leftValue, rightValue, operator)
	}, nil
}

func (p *filterParser) parseFunction(name string) (filterPredicate, error) {
	name = strings.ToLower(name)
	if name == "tags/any" || name == "tags/all" {
		return p.parseCollectionLambda(name)
	}
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
	if p.contract != nil {
		field := first.field
		if field == "" {
			field = second.field
		} else if second.field != "" {
			return nil, fmt.Errorf("%s requires one field and one literal", name)
		}
		if field == "" {
			return nil, fmt.Errorf("%s requires one field and one literal", name)
		}
		if err := p.validateField(field, "", name); err != nil {
			return nil, err
		}
	}
	return func(resource map[string]any) (bool, error) {
		left, err := first.evaluate(resource)
		if err != nil {
			return false, err
		}
		right, err := second.evaluate(resource)
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

func (p *filterParser) parseCollectionLambda(name string) (filterPredicate, error) {
	p.advance()
	if p.current.kind != filterIdentifier {
		return nil, fmt.Errorf("%s requires a lambda variable", name)
	}
	variable := p.current.text
	p.advance()
	if p.current.kind != filterColon {
		return nil, fmt.Errorf("%s requires a lambda expression", name)
	}
	p.advance()
	contract := p.contract
	p.contract = nil
	predicate, err := p.parseOr()
	p.contract = contract
	if err != nil {
		return nil, err
	}
	if p.current.kind != filterRightParen {
		return nil, fmt.Errorf("%s requires a closing parenthesis", name)
	}
	p.advance()
	if err := p.validateField("tags", "", strings.TrimPrefix(name, "tags/")); err != nil {
		return nil, err
	}
	tags := fieldOperand("tags")
	return func(resource map[string]any) (bool, error) {
		value, err := tags.evaluate(resource)
		if err != nil {
			return false, err
		}
		items, ok := value.([]any)
		if !ok {
			return strings.EqualFold(name, "tags/all"), nil
		}
		all := strings.EqualFold(name, "tags/all")
		for _, item := range items {
			result, err := predicate(map[string]any{variable: item})
			if err != nil {
				return false, err
			}
			if !all && result {
				return true, nil
			}
			if all && !result {
				return false, nil
			}
		}
		return all, nil
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
		return filterOperand{}, fmt.Errorf("expected a filter value, got %q", token.text)
	}
}

func literalOperand(value any) filterOperand {
	return filterOperand{evaluate: func(map[string]any) (any, error) { return value, nil }}
}

func fieldOperand(name string) filterOperand {
	return filterOperand{field: name, evaluate: func(resource map[string]any) (any, error) {
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
	}}
}

func (p *filterParser) validateField(field, operator, function string) error {
	if p.contract == nil {
		return nil
	}
	rule, found := p.contract[strings.ToLower(field)]
	if !found {
		return fmt.Errorf("filter field %q is not supported for this operation", field)
	}
	if operator != "" && !oneOf(operator, rule.operators...) {
		return fmt.Errorf("operator %s is not supported for filter field %q", operator, field)
	}
	if function != "" && !oneOf(function, rule.functions...) {
		return fmt.Errorf("function %s is not supported for filter field %q", function, field)
	}
	return nil
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
