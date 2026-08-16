package expression

import (
	"fmt"
	"math"
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

func (p *parser) take() Token {
	token := p.peek()
	if token.Kind != TokenEOF {
		p.pos++
	}
	return token
}

type varDecl struct {
	name string
	expr Expr
}

type blockExpr struct {
	vars   []varDecl
	result Expr
}

func (e blockExpr) eval(env *Env) (Value, error) {
	child := &Env{Bindings: map[string]Value{}}
	if env != nil {
		for name, value := range env.Bindings {
			child.Bindings[name] = value
		}
	}
	for _, decl := range e.vars {
		value, err := decl.expr.eval(child)
		if err != nil {
			return Null(), err
		}
		child.Bindings[decl.name] = value
	}
	return e.result.eval(child)
}

func wrapVars(vars []varDecl, expr Expr) Expr {
	if len(vars) == 0 {
		return expr
	}
	return blockExpr{vars: vars, result: expr}
}

func (p *parser) block() (Expr, error) {
	return p.blockBody()
}

func (p *parser) blockBody() (Expr, error) {
	var vars []varDecl
	for p.peek().Kind == TokenVar {
		decl, err := p.varDecl()
		if err != nil {
			return nil, err
		}
		vars = append(vars, decl)
	}
	switch p.peek().Kind {
	case TokenIf:
		expr, err := p.ifStmt()
		if err != nil {
			return nil, err
		}
		return wrapVars(vars, expr), nil
	case TokenReturn:
		expr, err := p.returnStmt()
		if err != nil {
			return nil, err
		}
		return wrapVars(vars, expr), nil
	case TokenEOF, TokenRBrace:
		return nil, fmt.Errorf("statement block must return a value")
	default:
		return nil, fmt.Errorf("statement %q is not implemented", p.peek().Lexeme)
	}
}

func (p *parser) returnStmt() (Expr, error) {
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
	return expr, nil
}

func (p *parser) ifStmt() (Expr, error) {
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
	if p.peek().Kind != TokenElse {
		return nil, fmt.Errorf("if requires else")
	}
	p.take()
	els, err := p.bracedBlock()
	if err != nil {
		return nil, err
	}
	return ternaryExpr{cond: cond, then: then, els: els}, nil
}

func (p *parser) bracedBlock() (Expr, error) {
	if p.peek().Kind != TokenLBrace {
		return nil, fmt.Errorf("expected '{'")
	}
	p.take()
	expr, err := p.blockBody()
	if err != nil {
		return nil, err
	}
	if p.peek().Kind != TokenRBrace {
		return nil, fmt.Errorf("expected '}'")
	}
	p.take()
	return expr, nil
}

func (p *parser) varDecl() (varDecl, error) {
	p.take()
	if p.peek().Kind != TokenIdent {
		return varDecl{}, fmt.Errorf("var requires a name")
	}
	name := p.take().Lexeme
	if p.peek().Kind != TokenAssign {
		return varDecl{}, fmt.Errorf("var requires '='")
	}
	p.take()
	expr, err := p.ternary()
	if err != nil {
		return varDecl{}, err
	}
	if p.peek().Kind != TokenSemicolon {
		return varDecl{}, fmt.Errorf("expected ';'")
	}
	p.take()
	return varDecl{name: name, expr: expr}, nil
}

func (p *parser) ternary() (Expr, error) {
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
			expr = memberExpr{recv: expr, name: p.take().Lexeme}
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
	case TokenIdent:
		return identExpr{name: token.Lexeme}, nil
	case TokenLParen:
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
	return recv.member(e.name)
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
