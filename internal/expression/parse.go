package expression

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Env is the identifier binding used during evaluation. A nil Env can still
// evaluate context-free expressions; identifiers fail as unbound.
type Env struct {
	Bindings map[string]Value
}

// Expr is a compiled policy expression.
type Expr interface {
	eval(*Env) (Value, error)
}

type literalExpr struct{ value Value }

func (e literalExpr) eval(*Env) (Value, error) { return e.value, nil }

type identExpr struct{ name string }

type memberExpr struct {
	recv Expr
	name string
	// typeArg is the type named in a generic call, as in `Body.As<string>()`.
	// Empty for an ordinary member.
	typeArg string
}

type indexExpr struct {
	recv, key Expr
}

type callExpr struct {
	recv Expr
	args []Expr
}

type unaryExpr struct {
	op TokenKind
	x  Expr
}

type binaryExpr struct {
	op          TokenKind
	left, right Expr
}

// lambdaExpr is `x => body`. It evaluates to a CALLABLE rather than to a
// result, so a LINQ operator invokes it through the same call machinery a
// policy uses for any other call.
type lambdaExpr struct {
	param string
	body  Expr
}

func (e lambdaExpr) eval(env *Env) (Value, error) {
	return Object(funcValue{fn: func(args []Value) (Value, error) {
		if len(args) != 1 {
			return Null(), fmt.Errorf("a lambda takes one argument")
		}
		// The body sees the bindings in scope where the lambda was WRITTEN,
		// plus its parameter. Copying rather than mutating keeps one element's
		// binding from leaking into the next iteration.
		child := &Env{Bindings: map[string]Value{}}
		if env != nil {
			for name, value := range env.Bindings {
				child.Bindings[name] = value
			}
		}
		child.Bindings[e.param] = args[0]
		return e.body.eval(child)
	}}), nil
}

// interpolationExpr is `$"text {hole} more"`.
//
// It is its own node rather than sugar for `+`, so that a null hole renders as
// EMPTY the way C# renders it, instead of depending on what this evaluator's
// addition happens to do with a null operand.
type interpolationExpr struct {
	segments []interpolationSegment
}

// A segment is literal text, or an expression when expr is non-nil.
type interpolationSegment struct {
	literal string
	expr    Expr
}

func (e interpolationExpr) eval(env *Env) (Value, error) {
	var out strings.Builder
	for _, segment := range e.segments {
		if segment.expr == nil {
			out.WriteString(segment.literal)
			continue
		}
		value, err := segment.expr.eval(env)
		if err != nil {
			return Null(), err
		}
		out.WriteString(value.String())
	}
	return String(out.String()), nil
}

// interpolation compiles a `$"..."` token, parsing each hole as an expression in
// its own right. The holes are split by the SAME scanner the lexer used to find
// the end of the string, so the two cannot disagree about where a hole stops.
func (p *parser) interpolation(token Token) (Expr, error) {
	parts, _, err := splitInterpolation(token.Lexeme[2:])
	if err != nil {
		return nil, err
	}
	expr := interpolationExpr{}
	for _, part := range parts {
		if !part.isHole {
			expr.segments = append(expr.segments, interpolationSegment{literal: part.text})
			continue
		}
		hole, err := parseHole(part.text)
		if err != nil {
			return nil, err
		}
		expr.segments = append(expr.segments, interpolationSegment{expr: hole})
	}
	return expr, nil
}

// parseHole compiles one hole. A hole is an expression, not a statement, and it
// must consume its whole source: trailing input means an alignment or format
// specifier -- `{value,10:F2}` -- which this evaluator does not implement, and
// failing loudly beats formatting it wrongly.
func parseHole(source string) (Expr, error) {
	tokens, err := scan(source)
	if err != nil {
		return nil, err
	}
	sub := &parser{tokens: tokens}
	hole, err := sub.ternary()
	if err != nil {
		return nil, err
	}
	if sub.peek().Kind != TokenEOF {
		return nil, fmt.Errorf("unexpected %q in an interpolated hole; alignment and format specifiers are not implemented", sub.peek().Lexeme)
	}
	return hole, nil
}

// newExpr is `new Type(args)` or an anonymous `new { a = x, b = y }`.
type newExpr struct {
	// construct is resolved at PARSE time, so evaluation has no lookup that
	// could fail: an unknown type is already a parse error naming it.
	construct func([]Value) (Value, error)
	args      []Expr
	// fields are the members of an anonymous object, in source order, because
	// an anonymous object is a record and its field order is how a policy reads
	// it back out.
	fields []newField
}

type newField struct {
	name  string
	value Expr
}

func (e newExpr) eval(env *Env) (Value, error) {
	if e.construct == nil {
		fields := make([]jsonField, 0, len(e.fields))
		for _, field := range e.fields {
			value, err := field.value.eval(env)
			if err != nil {
				return Null(), err
			}
			fields = append(fields, jsonField{name: field.name, value: value})
		}
		return anonymousObject(fields), nil
	}
	args := make([]Value, len(e.args))
	for i, arg := range e.args {
		value, err := arg.eval(env)
		if err != nil {
			return Null(), err
		}
		args[i] = value
	}
	return e.construct(args)
}

// construction parses `new`.
//
// Only a KNOWN type is accepted, the same way a cast only accepts a known type.
// `new XDocument(...)` is a parse error naming the type rather than something
// that compiles and then fails at request time: a policy author finds out when
// they save the policy, and the corpus gate keeps measuring what actually works
// rather than what merely parses.
func (p *parser) construction() (Expr, error) {
	// An anonymous object: `new { typ = "JWT", alg = "RS256" }`.
	if p.peek().Kind == TokenLBrace {
		return p.anonymousObject()
	}
	if p.peek().Kind != TokenIdent {
		return nil, fmt.Errorf("expected a type name after 'new'")
	}
	name := p.take().Lexeme
	// A namespace-qualified name, `new System.Random()`, names the same type.
	for p.peek().Kind == TokenDot && p.peekAt(1).Kind == TokenIdent {
		p.take()
		name = p.take().Lexeme
	}
	construct, ok := constructors[name]
	if !ok {
		return nil, fmt.Errorf("new %s is not implemented", name)
	}
	if p.peek().Kind != TokenLParen {
		return nil, fmt.Errorf("expected '(' after 'new %s'", name)
	}
	p.take()
	args, err := p.arguments()
	if err != nil {
		return nil, err
	}
	return newExpr{construct: construct, args: args}, nil
}

func (p *parser) anonymousObject() (Expr, error) {
	p.take()
	expr := newExpr{}
	for p.peek().Kind != TokenRBrace {
		if p.peek().Kind != TokenIdent {
			return nil, fmt.Errorf("expected a field name in an anonymous object")
		}
		name := p.take().Lexeme
		if p.peek().Kind != TokenAssign {
			return nil, fmt.Errorf("expected '=' after field %s", name)
		}
		p.take()
		value, err := p.ternary()
		if err != nil {
			return nil, err
		}
		expr.fields = append(expr.fields, newField{name: name, value: value})
		if p.peek().Kind == TokenComma {
			p.take()
			continue
		}
		break
	}
	if p.peek().Kind != TokenRBrace {
		return nil, fmt.Errorf("expected '}' to close an anonymous object")
	}
	p.take()
	return expr, nil
}

type ternaryExpr struct {
	cond, then, els Expr
}

// Parse lexes and compiles an APIM expression. Blocks may declare expression-
// scoped `var` locals, branch with `if`/`else`, and must `return` on every
// path. Other statements stay unimplemented so they cannot be silently skipped.
func Parse(source string) (Expr, Form, error) {
	tokens, form, err := Lex(source)
	if err != nil {
		return nil, form, err
	}
	parser := &parser{tokens: tokens}
	var expr Expr
	if form == FormBlock {
		expr, err = parser.block()
	} else {
		expr, err = parser.ternary()
	}
	if err != nil {
		return nil, form, err
	}
	if parser.peek().Kind != TokenEOF {
		return nil, form, fmt.Errorf("unexpected token %q", parser.peek().Lexeme)
	}
	return expr, form, nil
}

// Eval parses and evaluates a context-free APIM expression.
func Eval(source string) (Value, error) {
	return EvalEnv(source, nil)
}

// EvalEnv parses and evaluates an expression against identifier bindings.
func EvalEnv(source string, env *Env) (Value, error) {
	expr, _, err := Parse(source)
	if err != nil {
		return Null(), err
	}
	return expr.eval(env)
}

type parser struct {
	tokens []Token
	pos    int
}

func (p *parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Kind: TokenEOF}
	}
	return p.tokens[p.pos]
}

// peekAt looks ahead without consuming, which the cast check needs: deciding
// `(Type)` against `(expr)` requires seeing the token after the identifier.
func (p *parser) peekAt(offset int) Token {
	if p.pos+offset >= len(p.tokens) {
		return Token{Kind: TokenEOF}
	}
	return p.tokens[p.pos+offset]
}

func (p *parser) take() Token {
	token := p.peek()
	if token.Kind != TokenEOF {
		p.pos++
	}
	return token
}

// A policy block is a sequence of STATEMENTS, not a list of declarations with
// one result. That distinction is what lets `if (x == null) { x = ...; }` work:
// the branch falls through instead of having to produce a value, and the
// assignment is visible to the statements after it, which is how Microsoft's own
// policies write a fallback.
type stmt interface {
	// exec runs the statement. The second result reports whether it RETURNED,
	// so a return inside a branch stops the whole block rather than only the
	// branch.
	exec(env *Env) (Value, bool, error)
}

// declStmt introduces a local, `var x = ...` or `string x = ...`.
type declStmt struct {
	name string
	expr Expr
}

func (s declStmt) exec(env *Env) (Value, bool, error) {
	value, err := s.expr.eval(env)
	if err != nil {
		return Null(), false, err
	}
	env.Bindings[s.name] = value
	return Null(), false, nil
}

// assignStmt writes to a local that already exists. Assigning to a name nobody
// declared is an ERROR rather than an implicit declaration: C# rejects it, and
// accepting it here would turn a policy's typo into a silent new variable.
type assignStmt struct {
	name string
	expr Expr
}

func (s assignStmt) exec(env *Env) (Value, bool, error) {
	if _, declared := env.Bindings[s.name]; !declared {
		return Null(), false, fmt.Errorf("%s is not declared", s.name)
	}
	value, err := s.expr.eval(env)
	if err != nil {
		return Null(), false, err
	}
	env.Bindings[s.name] = value
	return Null(), false, nil
}

type returnStmt struct {
	expr Expr
}

func (s returnStmt) exec(env *Env) (Value, bool, error) {
	value, err := s.expr.eval(env)
	if err != nil {
		return Null(), false, err
	}
	return value, true, nil
}

// ifStmt runs one branch. An absent else is a branch that does nothing, which is
// the form `if (x == null) { x = fallback; }` takes.
type ifStmt struct {
	cond Expr
	then []stmt
	els  []stmt
}

func (s ifStmt) exec(env *Env) (Value, bool, error) {
	cond, err := s.cond.eval(env)
	if err != nil {
		return Null(), false, err
	}
	truth, ok := cond.AsBool()
	if !ok {
		return Null(), false, fmt.Errorf("an if condition must be true or false")
	}
	branch := s.els
	if truth {
		branch = s.then
	}
	return execScoped(branch, env)
}

// execScoped runs a branch's statements against the enclosing environment, so an
// assignment inside it is visible after it, and then removes the locals the
// branch DECLARED, so those are not. C# scopes a declaration to its block, and
// letting one escape would make a policy work here that fails in a tenant.
func execScoped(body []stmt, env *Env) (Value, bool, error) {
	restore := map[string]*Value{}
	for _, statement := range body {
		decl, ok := statement.(declStmt)
		if !ok {
			continue
		}
		if previous, existed := env.Bindings[decl.name]; existed {
			saved := previous
			restore[decl.name] = &saved
		} else {
			restore[decl.name] = nil
		}
	}
	value, returned, err := execStatements(body, env)
	for name, previous := range restore {
		if previous == nil {
			delete(env.Bindings, name)
			continue
		}
		env.Bindings[name] = *previous
	}
	return value, returned, err
}

func execStatements(body []stmt, env *Env) (Value, bool, error) {
	for _, statement := range body {
		value, returned, err := statement.exec(env)
		if err != nil {
			return Null(), false, err
		}
		if returned {
			return value, true, nil
		}
	}
	return Null(), false, nil
}

type blockExpr struct {
	body []stmt
}

func (e blockExpr) eval(env *Env) (Value, error) {
	child := &Env{Bindings: map[string]Value{}}
	if env != nil {
		for name, value := range env.Bindings {
			child.Bindings[name] = value
		}
	}
	value, returned, err := execStatements(e.body, child)
	if err != nil {
		return Null(), err
	}
	if !returned {
		// Unreachable for a block the parser accepted, which requires a
		// returning final statement. Kept because a block that fell off its end
		// answering null would be worse than one that says so.
		return Null(), fmt.Errorf("statement block did not return a value")
	}
	return value, nil
}

func (p *parser) block() (Expr, error) {
	body, err := p.statements(TokenEOF)
	if err != nil {
		return nil, err
	}
	if !alwaysReturns(body) {
		return nil, fmt.Errorf("statement block must return a value")
	}
	return blockExpr{body: body}, nil
}

// alwaysReturns reports whether a statement list returns on every path, which is
// what a policy block must do. An `if` counts only when BOTH branches do, so a
// fall-through branch cannot be mistaken for one that produces a value.
func alwaysReturns(body []stmt) bool {
	for _, statement := range body {
		switch typed := statement.(type) {
		case returnStmt:
			return true
		case ifStmt:
			if alwaysReturns(typed.then) && typed.els != nil && alwaysReturns(typed.els) {
				return true
			}
		}
	}
	return false
}

// statements reads statements until the closing token.
func (p *parser) statements(closer TokenKind) ([]stmt, error) {
	var body []stmt
	for p.peek().Kind != closer && p.peek().Kind != TokenEOF {
		statement, err := p.statement()
		if err != nil {
			return nil, err
		}
		body = append(body, statement)
	}
	return body, nil
}

func (p *parser) statement() (stmt, error) {
	if typed := p.typedLocal(); typed || p.peek().Kind == TokenVar {
		return p.varDecl(typed)
	}
	switch p.peek().Kind {
	case TokenIf:
		return p.ifStmt()
	case TokenReturn:
		return p.returnStmt()
	}
	// `name = value;` assigns to a local. `name value =` was already read as a
	// typed declaration above, so this cannot be one.
	if p.peek().Kind == TokenIdent && p.peekAt(1).Kind == TokenAssign {
		name := p.take().Lexeme
		p.take()
		expr, err := p.ternary()
		if err != nil {
			return nil, err
		}
		if p.peek().Kind != TokenSemicolon {
			return nil, fmt.Errorf("expected ';'")
		}
		p.take()
		return assignStmt{name: name, expr: expr}, nil
	}
	return nil, fmt.Errorf("statement %q is not implemented", p.peek().Lexeme)
}

func (p *parser) returnStmt() (stmt, error) {
	p.take()
	if p.peek().Kind == TokenSemicolon || p.peek().Kind == TokenEOF || p.peek().Kind == TokenRBrace {
		return nil, fmt.Errorf("return requires a value")
	}
	expr, err := p.ternary()
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenSemicolon {
		return nil, fmt.Errorf("expected ';'")
	}
	p.take()
	return returnStmt{expr: expr}, nil
}

func (p *parser) ifStmt() (stmt, error) {
	p.take()
	if p.peek().Kind != TokenLParen {
		return nil, fmt.Errorf("expected '('")
	}
	p.take()
	cond, err := p.ternary()
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenRParen {
		return nil, fmt.Errorf("expected ')'")
	}
	p.take()
	then, err := p.bracedBlock()
	if err != nil {
		return nil, err
	}
	// An `else` is OPTIONAL now. It used to be required because an if compiled
	// to a ternary and both arms had to produce a value; a branch that only
	// assigns produces nothing, and demanding an else would have rejected the
	// form Microsoft's own policies use for a fallback.
	if p.peek().Kind != TokenElse {
		return ifStmt{cond: cond, then: then}, nil
	}
	p.take()
	// `else if` chains without needing braces around the inner if.
	if p.peek().Kind == TokenIf {
		nested, err := p.ifStmt()
		if err != nil {
			return nil, err
		}
		return ifStmt{cond: cond, then: then, els: []stmt{nested}}, nil
	}
	els, err := p.bracedBlock()
	if err != nil {
		return nil, err
	}
	return ifStmt{cond: cond, then: then, els: els}, nil
}

func (p *parser) bracedBlock() ([]stmt, error) {
	if p.peek().Kind != TokenLBrace {
		return nil, fmt.Errorf("expected '{'")
	}
	p.take()
	body, err := p.statements(TokenRBrace)
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenRBrace {
		return nil, fmt.Errorf("expected '}'")
	}
	p.take()
	return body, nil
}

// typedLocal reports whether a declaration with an EXPLICIT type starts here,
// as in `string raw = ...` or `byte[] bytes = ...`, and consumes the type when
// it does.
//
// The shape is self-disambiguating: a C# expression statement cannot be two
// identifiers in a row, so `Ident Ident =` is always a declaration and never an
// expression. That is why no allowlist of type names is needed here, unlike a
// cast or a `new`, where the same text really is ambiguous.
//
// The declared type is then DISCARDED. This evaluator has no type system, so
// `string x = 5;` is accepted here and rejected by Azure -- a divergence in the
// permissive direction, recorded rather than hidden. Checking it properly means
// C#'s conversion rules, and guessing at them would reject valid policies, which
// is the worse failure.
func (p *parser) typedLocal() bool {
	start := p.pos
	if p.peek().Kind != TokenIdent {
		return false
	}
	p.take()
	// A namespace-qualified type, `System.Net.WebUtility name = ...`.
	for p.peek().Kind == TokenDot && p.peekAt(1).Kind == TokenIdent {
		p.take()
		p.take()
	}
	// An array type, `byte[] name = ...`.
	if p.peek().Kind == TokenLBracket && p.peekAt(1).Kind == TokenRBracket {
		p.take()
		p.take()
	}
	if p.peek().Kind == TokenIdent && p.peekAt(1).Kind == TokenAssign {
		return true
	}
	p.pos = start
	return false
}

// varDecl parses a local declaration. The type, if one was written, has already
// been consumed by typedLocal; `var` has not.
func (p *parser) varDecl(typed bool) (stmt, error) {
	if !typed {
		p.take()
	}
	if p.peek().Kind != TokenIdent {
		return nil, fmt.Errorf("var requires a name")
	}
	name := p.take().Lexeme
	if p.peek().Kind != TokenAssign {
		return nil, fmt.Errorf("var requires '='")
	}
	p.take()
	expr, err := p.ternary()
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenSemicolon {
		return nil, fmt.Errorf("expected ';'")
	}
	p.take()
	return declStmt{name: name, expr: expr}, nil
}

func (p *parser) ternary() (Expr, error) {
	if lambda, ok, err := p.lambda(); ok || err != nil {
		return lambda, err
	}
	cond, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenQuestion {
		return cond, nil
	}
	p.take()
	then, err := p.ternary()
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenColon {
		return nil, fmt.Errorf("expected ':' in conditional expression")
	}
	p.take()
	els, err := p.ternary()
	if err != nil {
		return nil, err
	}
	return ternaryExpr{cond: cond, then: then, els: els}, nil
}

func (p *parser) or() (Expr, error)  { return p.binary(p.and, TokenOr) }
func (p *parser) and() (Expr, error) { return p.binary(p.equality, TokenAnd) }
func (p *parser) equality() (Expr, error) {
	return p.binary(p.comparison, TokenEq, TokenNe)
}
func (p *parser) comparison() (Expr, error) {
	return p.binary(p.term, TokenLt, TokenLe, TokenGt, TokenGe)
}
func (p *parser) term() (Expr, error) { return p.binary(p.factor, TokenPlus, TokenMinus) }
func (p *parser) factor() (Expr, error) {
	return p.binary(p.unary, TokenStar, TokenSlash, TokenPercent)
}

func (p *parser) binary(next func() (Expr, error), ops ...TokenKind) (Expr, error) {
	left, err := next()
	if err != nil {
		return nil, err
	}
	for {
		kind := p.peek().Kind
		matched := false
		for _, op := range ops {
			if kind == op {
				matched = true
				break
			}
		}
		if !matched {
			return left, nil
		}
		p.take()
		right, err := next()
		if err != nil {
			return nil, err
		}
		left = binaryExpr{op: kind, left: left, right: right}
	}
}

func (p *parser) unary() (Expr, error) {
	switch p.peek().Kind {
	case TokenNot, TokenPlus, TokenMinus:
		op := p.take().Kind
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return unaryExpr{op: op, x: x}, nil
	default:
		return p.postfix()
	}
}

func (p *parser) postfix() (Expr, error) {
	expr, err := p.atom()
	if err != nil {
		return nil, err
	}
	for {
		switch p.peek().Kind {
		case TokenDot:
			p.take()
			if p.peek().Kind != TokenIdent {
				return nil, fmt.Errorf("expected member name")
			}
			name := p.take().Lexeme
			// `As<string>()` is a generic call; `a.b < c` is a comparison. They
			// are distinguishable only by looking past the `<`, so the attempt
			// rewinds rather than committing.
			expr = memberExpr{recv: expr, name: name, typeArg: p.typeArgument()}
		case TokenLBracket:
			p.take()
			key, err := p.ternary()
			if err != nil {
				return nil, err
			}
			if p.peek().Kind != TokenRBracket {
				return nil, fmt.Errorf("expected ']'")
			}
			p.take()
			expr = indexExpr{recv: expr, key: key}
		case TokenLParen:
			p.take()
			args, err := p.arguments()
			if err != nil {
				return nil, err
			}
			expr = callExpr{recv: expr, args: args}
		default:
			return expr, nil
		}
	}
}

func (p *parser) arguments() ([]Expr, error) {
	if p.peek().Kind == TokenRParen {
		p.take()
		return nil, nil
	}
	var args []Expr
	for {
		arg, err := p.ternary()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		switch p.peek().Kind {
		case TokenComma:
			p.take()
		case TokenRParen:
			p.take()
			return args, nil
		default:
			return nil, fmt.Errorf("expected ')'")
		}
	}
}

func (p *parser) atom() (Expr, error) {
	token := p.take()
	switch token.Kind {
	case TokenTrue, TokenFalse, TokenNull, TokenNumber, TokenString:
		return literalExpr{value: token.Literal}, nil
	case TokenInterpolated:
		return p.interpolation(token)
	case TokenNew:
		return p.construction()
	case TokenIdent:
		return identExpr{name: token.Lexeme}, nil
	case TokenLParen:
		// A C# CAST, `(Type)expr`, which APIM's documented policies use
		// constantly: `(string)`, `(int)`, `(JObject)`, and for the credential
		// manager `((Authorization)context.Variables["x"]).AccessToken`.
		//
		// `(a)(b)` and `(a)` are genuinely ambiguous between a cast and a
		// parenthesised expression, and resolving that needs type information a
		// policy expression does not carry. Recognising only a KNOWN type name
		// removes the ambiguity: `(Authorization)` is always a cast, `(total)`
		// is always a parenthesised identifier.
		if p.peek().Kind == TokenIdent && castTypes[p.peek().Lexeme] && p.peekAt(1).Kind == TokenRParen {
			castType := p.take().Lexeme
			p.take() // the ')'
			operand, err := p.unary()
			if err != nil {
				return nil, err
			}
			return castExpr{typeName: castType, operand: operand}, nil
		}
		expr, err := p.ternary()
		if err != nil {
			return nil, err
		}
		if p.peek().Kind != TokenRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.take()
		return expr, nil
	case TokenEOF:
		return nil, fmt.Errorf("expected expression")
	default:
		return nil, fmt.Errorf("unexpected token %q", token.Lexeme)
	}
}

func (e identExpr) eval(env *Env) (Value, error) {
	if env == nil {
		return Null(), fmt.Errorf("unbound identifier %s", e.name)
	}
	value, ok := env.Bindings[e.name]
	if !ok {
		return Null(), fmt.Errorf("unbound identifier %s", e.name)
	}
	return value, nil
}

func (e memberExpr) eval(env *Env) (Value, error) {
	recv, err := e.recv.eval(env)
	if err != nil {
		return Null(), err
	}
	if e.typeArg != "" {
		generic, ok := recv.obj.(genericHost)
		if !ok {
			return Null(), fmt.Errorf("%s is not a generic member", e.name)
		}
		return generic.genericMember(e.name, e.typeArg)
	}
	return recv.member(e.name)
}

// genericHost is implemented by the few hosts with a generic member. Optional,
// so the other fifteen hosts are untouched by a feature only one of them has.
type genericHost interface {
	genericMember(name, typeArg string) (Value, error)
}

func (e indexExpr) eval(env *Env) (Value, error) {
	recv, err := e.recv.eval(env)
	if err != nil {
		return Null(), err
	}
	key, err := e.key.eval(env)
	if err != nil {
		return Null(), err
	}
	return recv.index(key)
}

func (e callExpr) eval(env *Env) (Value, error) {
	recv, err := e.recv.eval(env)
	if err != nil {
		return Null(), err
	}
	args := make([]Value, len(e.args))
	for i, arg := range e.args {
		value, err := arg.eval(env)
		if err != nil {
			return Null(), err
		}
		args[i] = value
	}
	return recv.call(args)
}

func (e unaryExpr) eval(env *Env) (Value, error) {
	value, err := e.x.eval(env)
	if err != nil {
		return Null(), err
	}
	switch e.op {
	case TokenNot:
		truth, ok := value.AsBool()
		if !ok {
			return Null(), fmt.Errorf("operator '!' requires a boolean")
		}
		return Bool(!truth), nil
	case TokenPlus:
		if !value.IsNumeric() {
			return Null(), fmt.Errorf("unary '+' requires a number")
		}
		return value, nil
	default:
		if !value.IsNumeric() {
			return Null(), fmt.Errorf("unary '-' requires a number")
		}
		if value.kind == KindDouble {
			return Double(-value.dbl), nil
		}
		return Int(-value.num), nil
	}
}

func (e binaryExpr) eval(env *Env) (Value, error) {
	if e.op == TokenAnd || e.op == TokenOr {
		return e.evalLogic(env)
	}
	left, err := e.left.eval(env)
	if err != nil {
		return Null(), err
	}
	right, err := e.right.eval(env)
	if err != nil {
		return Null(), err
	}
	switch e.op {
	case TokenPlus:
		return add(left, right)
	case TokenMinus:
		return numericBinary(left, right, func(a, b int64) (Value, error) { return Int(a - b), nil }, func(a, b float64) float64 { return a - b })
	case TokenStar:
		return numericBinary(left, right, func(a, b int64) (Value, error) { return Int(a * b), nil }, func(a, b float64) float64 { return a * b })
	case TokenSlash:
		return numericBinary(left, right, func(a, b int64) (Value, error) {
			if b == 0 {
				return Null(), fmt.Errorf("division by zero")
			}
			return Int(a / b), nil
		}, func(a, b float64) float64 { return a / b })
	case TokenPercent:
		return numericBinary(left, right, func(a, b int64) (Value, error) {
			if b == 0 {
				return Null(), fmt.Errorf("division by zero")
			}
			return Int(a % b), nil
		}, func(a, b float64) float64 { return remainder(a, b) })
	case TokenEq:
		return Bool(equal(left, right)), nil
	case TokenNe:
		return Bool(!equal(left, right)), nil
	case TokenLt, TokenLe, TokenGt, TokenGe:
		order, err := compare(left, right)
		if err != nil {
			return Null(), err
		}
		switch e.op {
		case TokenLt:
			return Bool(order < 0), nil
		case TokenLe:
			return Bool(order <= 0), nil
		case TokenGt:
			return Bool(order > 0), nil
		default:
			return Bool(order >= 0), nil
		}
	default:
		return Null(), fmt.Errorf("unsupported operator")
	}
}

func (e binaryExpr) evalLogic(env *Env) (Value, error) {
	left, err := e.left.eval(env)
	if err != nil {
		return Null(), err
	}
	truth, ok := left.AsBool()
	if !ok {
		return Null(), fmt.Errorf("logical operator requires a boolean")
	}
	if e.op == TokenAnd && !truth {
		return Bool(false), nil
	}
	if e.op == TokenOr && truth {
		return Bool(true), nil
	}
	right, err := e.right.eval(env)
	if err != nil {
		return Null(), err
	}
	next, ok := right.AsBool()
	if !ok {
		return Null(), fmt.Errorf("logical operator requires a boolean")
	}
	return Bool(next), nil
}

func (e ternaryExpr) eval(env *Env) (Value, error) {
	cond, err := e.cond.eval(env)
	if err != nil {
		return Null(), err
	}
	truth, ok := cond.AsBool()
	if !ok {
		return Null(), fmt.Errorf("conditional requires a boolean")
	}
	if truth {
		return e.then.eval(env)
	}
	return e.els.eval(env)
}

func add(left, right Value) (Value, error) {
	if left.kind == KindString || right.kind == KindString {
		return String(left.String() + right.String()), nil
	}
	return numericBinary(left, right, func(a, b int64) (Value, error) { return Int(a + b), nil }, func(a, b float64) float64 { return a + b })
}

func numericBinary(left, right Value, ints func(int64, int64) (Value, error), floats func(float64, float64) float64) (Value, error) {
	if !left.IsNumeric() || !right.IsNumeric() {
		return Null(), fmt.Errorf("operator requires numeric operands")
	}
	if left.kind == KindDouble || right.kind == KindDouble {
		leftNumber, _ := left.AsNumber()
		rightNumber, _ := right.AsNumber()
		return Double(floats(leftNumber, rightNumber)), nil
	}
	return ints(left.num, right.num)
}

func compare(left, right Value) (int, error) {
	if left.IsNumeric() && right.IsNumeric() {
		leftNumber, _ := left.AsNumber()
		rightNumber, _ := right.AsNumber()
		switch {
		case leftNumber < rightNumber:
			return -1, nil
		case leftNumber > rightNumber:
			return 1, nil
		default:
			return 0, nil
		}
	}
	if left.kind == KindString && right.kind == KindString {
		return strings.Compare(left.str, right.str), nil
	}
	return 0, fmt.Errorf("incomparable operands")
}

func remainder(left, right float64) float64 {
	if right == 0 {
		return math.NaN()
	}
	return left - float64(int64(left/right))*right
}

// castTypes are the type names a policy expression may cast to. An allowlist
// rather than "any identifier", because that is what makes `(Type)x` decidable
// against a parenthesised expression without type information.
var castTypes = map[string]bool{
	"string": true, "int": true, "long": true, "bool": true, "double": true,
	"JObject": true, "JArray": true, "JValue": true, "JToken": true,
	"IResponse": true, "IRequest": true, "Authorization": true,
}

// castExpr evaluates its operand and converts where the conversion is
// meaningful.
//
// A cast to an object type is a no-op: the emulator's value model already
// carries the object, and refusing would reject the exact expressions Azure's
// documentation tells people to write. A cast to a scalar DOES convert, because
// `(int)context.Variables["n"]` is how a policy turns a stored string into a
// number and returning the string would make arithmetic on it wrong.
type castExpr struct {
	typeName string
	operand  Expr
}

func (e castExpr) eval(env *Env) (Value, error) {
	value, err := e.operand.eval(env)
	if err != nil {
		return Null(), err
	}
	switch e.typeName {
	case "string":
		if value.IsNull() {
			return String(""), nil
		}
		return String(value.String()), nil
	case "int", "long":
		number, ok := castNumber(value)
		if !ok {
			return Null(), fmt.Errorf("cannot cast %v to %s", value.Kind(), e.typeName)
		}
		return Int(int64(number)), nil
	case "double":
		number, ok := castNumber(value)
		if !ok {
			return Null(), fmt.Errorf("cannot cast %v to double", value.Kind())
		}
		return Double(number), nil
	case "bool":
		if value.kind == KindBool {
			return value, nil
		}
		if value.kind == KindString {
			parsed, err := strconv.ParseBool(value.str)
			if err != nil {
				return Null(), fmt.Errorf("cannot cast %q to bool", value.str)
			}
			return Bool(parsed), nil
		}
		return Null(), fmt.Errorf("cannot cast %v to bool", value.Kind())
	default:
		// An object cast asserts the shape rather than converting it.
		return value, nil
	}
}

// castNumber converts for a numeric cast, INCLUDING from a string.
//
// This is a deliberate, documented divergence from C#, where `(int)` on a
// boxed string throws and you would write `int.Parse`. It exists because this
// emulator's `context.Variables` is map[string]string, so every variable is a
// string no matter what produced it, and a strict cast would make
// `(int)context.Variables["x"]` fail for every policy that Azure accepts.
//
// The real gap is the string-only variable model, not the cast. Refusing here
// would not surface that gap, it would just make documented policies
// unrunnable; converting makes them run and leaves the gap where it belongs.
func castNumber(value Value) (float64, bool) {
	if number, ok := value.AsNumber(); ok {
		return number, true
	}
	if value.kind != KindString {
		return 0, false
	}
	number, err := strconv.ParseFloat(strings.TrimSpace(value.str), 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

// typeArgument reads `<TypeName>` when it introduces a generic CALL.
//
// The `<` of `Body.As<string>()` and the `<` of `a.Count < 3` are the same
// token, and C# resolves the ambiguity with type information a policy
// expression does not carry. The rule here is narrower and decidable: a type
// argument is only recognised when the very next tokens are `< identifier > (`.
// Anything else rewinds and the `<` is left for the comparison parser, so no
// existing expression changes meaning.
// lambda parses `x => body`, the anonymous function a LINQ operator takes.
//
// One parameter is what policies write. `(a, b) => ...` is NOT accepted: it
// would have to be told apart from a parenthesised expression, and refusing it
// keeps a two-parameter lambda a clear error rather than a confusing one.
func (p *parser) lambda() (Expr, bool, error) {
	if p.peek().Kind != TokenIdent || p.peekAt(1).Kind != TokenArrow {
		return nil, false, nil
	}
	param := p.take().Lexeme
	p.take()
	body, err := p.ternary()
	if err != nil {
		return nil, true, err
	}
	return lambdaExpr{param: param, body: body}, true, nil
}

func (p *parser) typeArgument() string {
	start := p.pos
	if p.peek().Kind != TokenLt {
		return ""
	}
	p.take()
	if p.peek().Kind != TokenIdent {
		p.pos = start
		return ""
	}
	name := p.take().Lexeme
	if p.peek().Kind != TokenGt {
		p.pos = start
		return ""
	}
	p.take()
	if p.peek().Kind != TokenLParen {
		p.pos = start
		return ""
	}
	return name
}
