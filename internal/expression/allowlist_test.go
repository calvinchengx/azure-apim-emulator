package expression

import (
	"encoding/json"
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestAllowlistMatchesCheckedInLedger(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", "expression-members.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Members []Member `json:"members"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if diff := memberDiff(document.Members, Allowlist()); diff != "" {
		t.Fatalf("expression-members.json drifted from Allowlist(): %s", diff)
	}
}

func TestBinderCasesMatchAllowlist(t *testing.T) {
	bound := boundByType(Allowlist())
	found := binderCases(t)
	for typ, names := range found {
		for name := range names {
			if bound[typ][name] {
				continue
			}
			t.Fatalf("binder exposes %s.%s without an allowlist bound entry", typ, name)
		}
	}
	for typ, names := range bound {
		if typ == "value" || typ == "string" {
			continue
		}
		for name := range names {
			if !found[typ][name] {
				t.Fatalf("allowlist bound %s.%s is missing from the binder", typ, name)
			}
		}
	}
	for _, member := range Allowlist() {
		if member.Status != MemberPlanned {
			continue
		}
		if found[member.Type][member.Name] {
			t.Fatalf("planned %s.%s is bound; update the allowlist status", member.Type, member.Name)
		}
	}
}

func TestAllowlistBoundMembersEvaluate(t *testing.T) {
	env := Bind(Context{
		Request:      httptest.NewRequest(http.MethodGet, "https://api.example/pets?x=1", nil),
		Response:     &http.Response{StatusCode: http.StatusOK},
		Variables:    map[string]string{"route": "blue"},
		LastError:    errors.New("temporary"),
		Api:          &ApiContext{Id: "pets", Name: "Pets", Path: "pets"},
		Operation:    &OperationContext{Id: "list", Name: "List", Method: http.MethodGet, UrlTemplate: "/"},
		Product:      &NamedContext{Id: "starter", Name: "Starter"},
		Subscription: &NamedContext{Id: "dev", Name: "Dev"},
		User:         &NamedContext{Id: "ada", Name: "Ada"},
		Deployment:   &DeploymentContext{ServiceName: "emulator", Region: "local"},
	})
	cases := map[string]string{
		"context.Request":           "@(context.Request != null)",
		"context.Response":          "@(context.Response != null)",
		"context.Variables":         "@(context.Variables.ContainsKey('route'))",
		"context.LastError":         "@(context.LastError != null)",
		"context.Api":               "@(context.Api != null)",
		"context.Operation":         "@(context.Operation != null)",
		"context.Product":           "@(context.Product != null)",
		"context.Subscription":      "@(context.Subscription != null)",
		"context.User":              "@(context.User != null)",
		"context.Deployment":        "@(context.Deployment != null)",
		"Request.Method":            "@(context.Request.Method)",
		"Request.Url":               "@(context.Request.Url != null)",
		"Request.URL":               "@(context.Request.URL != null)",
		"Request.Headers":           "@(context.Request.Headers.Get('X') == '')",
		"Request.IpAddress":         "@(context.Request.IpAddress != null)",
		"Request.Body":              "@(context.Request.Body.AsString() == '')",
		"Response.StatusCode":       "@(context.Response.StatusCode)",
		"Response.StatusReason":     "@(context.Response.StatusReason)",
		"Response.Headers":          "@(context.Response.Headers.Get('X') == '')",
		"Response.Body":             "@(context.Response.Body.AsString() == '')",
		"LastError.Message":         "@(context.LastError.Message)",
		"Url.Path":                  "@(context.Request.Url.Path)",
		"Url.Host":                  "@(context.Request.Url.Host)",
		"Url.Scheme":                "@(context.Request.Url.Scheme)",
		"Url.Query":                 "@(context.Request.Url.Query)",
		"Url.QueryString":           "@(context.Request.Url.QueryString)",
		"Url.Port":                  "@(context.Request.Url.Port)",
		"Headers.Get":               "@(context.Request.Headers.Get('X'))",
		"Headers.GetValueOrDefault": "@(context.Request.Headers.GetValueOrDefault('X', 'n'))",
		"Variables.ContainsKey":     "@(context.Variables.ContainsKey('route'))",
		"Body.AsString":             "@(context.Request.Body.AsString())",
		"Api.Id":                    "@(context.Api.Id)",
		"Api.Name":                  "@(context.Api.Name)",
		"Api.Path":                  "@(context.Api.Path)",
		"Operation.Id":              "@(context.Operation.Id)",
		"Operation.Name":            "@(context.Operation.Name)",
		"Operation.Method":          "@(context.Operation.Method)",
		"Operation.UrlTemplate":     "@(context.Operation.UrlTemplate)",
		"Product.Id":                "@(context.Product.Id)",
		"Product.Name":              "@(context.Product.Name)",
		"Subscription.Id":           "@(context.Subscription.Id)",
		"Subscription.Name":         "@(context.Subscription.Name)",
		"User.Id":                   "@(context.User.Id)",
		"User.Name":                 "@(context.User.Name)",
		"Deployment.ServiceName":    "@(context.Deployment.ServiceName)",
		"Deployment.Region":         "@(context.Deployment.Region)",
		"value.ToString":            "@(1.ToString())",
		"string.Length":             "@('ab'.Length)",
	}
	for _, member := range Allowlist() {
		if member.Status != MemberBound {
			continue
		}
		source, ok := cases[member.Type+"."+member.Name]
		if !ok {
			t.Fatalf("no evaluation case for bound %s.%s", member.Type, member.Name)
		}
		if _, err := EvalEnv(source, env); err != nil {
			t.Fatalf("%s (%s): %v", member.Type+"."+member.Name, source, err)
		}
	}
	for _, member := range Allowlist() {
		if member.Status != MemberPlanned {
			continue
		}
		source := "@(context." + member.Type + "." + member.Name + ")"
		if member.Type == "context" {
			source = "@(context." + member.Name + ")"
		} else if member.Type == "Request" || member.Type == "Response" {
			source = "@(context." + member.Type + "." + member.Name + ")"
		} else if member.Type == "Url" {
			source = "@(context.Request.Url." + member.Name + ")"
		} else if member.Type == "Headers" {
			source = "@(context.Request.Headers." + member.Name + ")"
		} else if member.Type == "Variables" {
			source = "@(context.Variables." + member.Name + ")"
		} else if member.Type == "Body" {
			source = "@(context.Request.Body." + member.Name + ")"
		} else if member.Type == "LastError" {
			source = "@(context.LastError." + member.Name + ")"
		} else {
			source = "@(context." + member.Type + "." + member.Name + ")"
		}
		if _, err := EvalEnv(source, env); err == nil {
			t.Fatalf("planned %s.%s evaluated", member.Type, member.Name)
		}
	}
}

func boundByType(members []Member) map[string]map[string]bool {
	result := map[string]map[string]bool{}
	for _, member := range members {
		if member.Status != MemberBound {
			continue
		}
		if result[member.Type] == nil {
			result[member.Type] = map[string]bool{}
		}
		result[member.Type][member.Name] = true
	}
	return result
}

func binderCases(t *testing.T) map[string]map[string]bool {
	t.Helper()
	hosts := map[string][]string{
		"contextHost":    {"context"},
		"requestHost":    {"Request"},
		"responseHost":   {"Response"},
		"lastErrorHost":  {"LastError"},
		"urlHost":        {"Url"},
		"headerHost":     {"Headers"},
		"mapHost":        {"Variables"},
		"bodyHost":       {"Body"},
		"apiHost":        {"Api"},
		"operationHost":  {"Operation"},
		"namedHost":      {"Product", "Subscription", "User"},
		"deploymentHost": {"Deployment"},
	}
	file, err := goparser.ParseFile(token.NewFileSet(), "context.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "member" || fn.Recv == nil || len(fn.Recv.List) == 0 {
			return true
		}
		recv := receiverName(fn.Recv.List[0].Type)
		types, ok := hosts[recv]
		if !ok {
			t.Fatalf("binder host %s is not mapped in the allowlist test", recv)
		}
		for _, stmt := range fn.Body.List {
			sw, ok := stmt.(*ast.SwitchStmt)
			if !ok {
				continue
			}
			for _, clause := range sw.Body.List {
				caseClause, ok := clause.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range caseClause.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok {
						continue
					}
					name := lit.Value[1 : len(lit.Value)-1]
					for _, typ := range types {
						if found[typ] == nil {
							found[typ] = map[string]bool{}
						}
						found[typ][name] = true
					}
				}
			}
		}
		return true
	})
	if len(found) == 0 {
		t.Fatal("no binder member cases found")
	}
	return found
}

func receiverName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	ident, _ := expr.(*ast.Ident)
	if ident == nil {
		return ""
	}
	return ident.Name
}

func memberDiff(got, want []Member) string {
	normalize := func(values []Member) []string {
		items := make([]string, 0, len(values))
		for _, value := range values {
			items = append(items, value.Type+"."+value.Name+"="+string(value.Status))
		}
		sort.Strings(items)
		return items
	}
	left, right := normalize(got), normalize(want)
	if len(left) == len(right) {
		equal := true
		for index := range left {
			if left[index] != right[index] {
				equal = false
				break
			}
		}
		if equal {
			return ""
		}
	}
	return "got " + joinMembers(left) + "; want " + joinMembers(right)
}

func joinMembers(values []string) string {
	raw, _ := json.Marshal(values)
	return string(raw)
}
