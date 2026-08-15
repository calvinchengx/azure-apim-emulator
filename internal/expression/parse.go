package expression

import (
	"fmt"
	"math"
	"strings"
)

// Expr is a compiled policy expression.
type Expr interface {
	eval() (Value, error)
}

type literalExpr struct{ value Value }

func (e literalExpr) eval() (Value, error) { return e.value, nil }

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

// Parse lexes and compiles a context-free APIM expression. Statement blocks,
// identifiers, member access, calls, and indexing remain unsupported so they
// cannot be silently skipped.
func Parse(source string) (Expr, Form, error) {
	tokens, form, err := Lex(source)
	if err != nil {
		return nil, form, err
	}
	if form == FormBlock {
		return nil, form, fmt.Errorf("statement blocks are not implemented")
	}
	parser := &parser{tokens: tokens}
	expr, err := parser.ternary()
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
	expr, _, err := Parse(source)
	if err != nil {
		return Null(), err
	}
	return expr.eval()
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
		return p.primary()
	}
}

func (p *parser) primary() (Expr, error) {
	token := p.take()
	switch token.Kind {
	case TokenTrue, TokenFalse, TokenNull, TokenNumber, TokenString:
		return literalExpr{value: token.Literal}, nil
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

func (e unaryExpr) eval() (Value, error) {
	value, err := e.x.eval()
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

func (e binaryExpr) eval() (Value, error) {
	if e.op == TokenAnd || e.op == TokenOr {
		return e.evalLogic()
	}
	left, err := e.left.eval()
	if err != nil {
		return Null(), err
	}
	right, err := e.right.eval()
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

func (e binaryExpr) evalLogic() (Value, error) {
	left, err := e.left.eval()
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
	right, err := e.right.eval()
	if err != nil {
		return Null(), err
	}
	next, ok := right.AsBool()
	if !ok {
		return Null(), fmt.Errorf("logical operator requires a boolean")
	}
	return Bool(next), nil
}

func (e ternaryExpr) eval() (Value, error) {
	cond, err := e.cond.eval()
	if err != nil {
		return Null(), err
	}
	truth, ok := cond.AsBool()
	if !ok {
		return Null(), fmt.Errorf("conditional requires a boolean")
	}
	if truth {
		return e.then.eval()
	}
	return e.els.eval()
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
