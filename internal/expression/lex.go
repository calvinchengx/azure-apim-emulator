package expression

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Form is the surface syntax of an APIM expression.
type Form int

const (
	// FormBare is a raw C# snippet with no @(...) / @{...} wrapper.
	FormBare Form = iota
	// FormExpression is @(expression).
	FormExpression
	// FormBlock is @{ statements; return value; }.
	FormBlock
)

// TokenKind identifies one lexer token.
type TokenKind int

const (
	TokenEOF TokenKind = iota
	TokenIdent
	TokenNumber
	TokenString
	// TokenInterpolated is a `$"..."` string. Its Lexeme carries the whole
	// literal, holes included, because the parser splits it with the same
	// scanner the lexer used to find its end.
	TokenInterpolated
	TokenTrue
	TokenFalse
	TokenNull
	TokenPlus
	TokenMinus
	TokenStar
	TokenSlash
	TokenPercent
	TokenEq
	TokenNe
	TokenLt
	TokenLe
	TokenGt
	TokenGe
	TokenAnd
	TokenOr
	TokenNot
	TokenDot
	TokenComma
	TokenColon
	TokenQuestion
	// TokenQuestionDot is `?.`, the null-conditional access, and
	// TokenQuestionBracket is `?[`, the null-conditional index. TokenCoalesce
	// is `??`.
	TokenQuestionDot
	TokenQuestionBracket
	TokenCoalesce
	TokenAssign
	TokenArrow
	TokenInc
	TokenDec
	TokenLParen
	TokenRParen
	TokenLBracket
	TokenRBracket
	TokenLBrace
	TokenRBrace
	TokenSemicolon
	TokenReturn
	TokenIf
	TokenElse
	TokenVar
	TokenNew
)

// Token is one scanned symbol. Literal is set for numbers, strings, and keywords
// that are values (true/false/null).
type Token struct {
	Kind    TokenKind
	Lexeme  string
	Literal Value
	Offset  int
}

var keywords = map[string]TokenKind{
	"true":   TokenTrue,
	"false":  TokenFalse,
	"null":   TokenNull,
	"return": TokenReturn,
	"if":     TokenIf,
	"else":   TokenElse,
	"var":    TokenVar,
	"new":    TokenNew,
}

// Lex tokenizes an APIM policy expression. Wrappers @(...) and @{...} are
// stripped after their matching closer is found so nested parens, braces, and
// string literals do not confuse the form detector.
func Lex(source string) ([]Token, Form, error) {
	source = strings.TrimSpace(source)
	form := FormBare
	inner := source
	switch {
	case strings.HasPrefix(source, "@("):
		form = FormExpression
		closeAt, err := matchingCloser(source, 1, '(', ')')
		if err != nil {
			return nil, form, err
		}
		if strings.TrimSpace(source[closeAt+1:]) != "" {
			return nil, form, fmt.Errorf("unexpected input after expression")
		}
		inner = source[2:closeAt]
	case strings.HasPrefix(source, "@{"):
		form = FormBlock
		closeAt, err := matchingCloser(source, 1, '{', '}')
		if err != nil {
			return nil, form, err
		}
		if strings.TrimSpace(source[closeAt+1:]) != "" {
			return nil, form, fmt.Errorf("unexpected input after expression")
		}
		inner = source[2:closeAt]
	case strings.HasPrefix(source, "@"):
		return nil, FormBare, fmt.Errorf("invalid expression wrapper")
	}
	tokens, err := scan(inner)
	return tokens, form, err
}

func matchingCloser(source string, open int, left, right byte) (int, error) {
	depth := 0
	i := open
	for i < len(source) {
		switch source[i] {
		case left:
			depth++
			i++
		case right:
			depth--
			if depth == 0 {
				return i, nil
			}
			i++
		case '"', '\'':
			next, err := skipString(source, i, source[i], false)
			if err != nil {
				return 0, err
			}
			i = next
		case '$':
			if i+1 < len(source) && source[i+1] == '"' {
				_, closeAt, err := splitInterpolation(source[i+2:])
				if err != nil {
					return 0, err
				}
				i = i + 2 + closeAt + 1
				continue
			}
			i++
		case '@':
			if i+1 < len(source) && source[i+1] == '"' {
				next, err := skipString(source, i+1, '"', true)
				if err != nil {
					return 0, err
				}
				i = next
				continue
			}
			i++
		case '/':
			next, err := skipComment(source, i)
			if err != nil {
				return 0, err
			}
			if next == i {
				i++
				continue
			}
			i = next
		default:
			i++
		}
	}
	return 0, fmt.Errorf("unclosed expression wrapper")
}

func skipString(source string, start int, quote byte, verbatim bool) (int, error) {
	i := start + 1
	for i < len(source) {
		if source[i] == quote {
			if verbatim && i+1 < len(source) && source[i+1] == '"' {
				i += 2
				continue
			}
			return i + 1, nil
		}
		if !verbatim && source[i] == '\\' {
			if i+1 >= len(source) {
				return 0, fmt.Errorf("unterminated string")
			}
			i += 2
			continue
		}
		if !verbatim && (source[i] == '\n' || source[i] == '\r') {
			return 0, fmt.Errorf("unterminated string")
		}
		i++
	}
	return 0, fmt.Errorf("unterminated string")
}

func skipComment(source string, start int) (int, error) {
	if start+1 >= len(source) {
		return start, nil
	}
	switch source[start+1] {
	case '/':
		i := start + 2
		for i < len(source) && source[i] != '\n' {
			i++
		}
		return i, nil
	case '*':
		i := start + 2
		for i+1 < len(source) {
			if source[i] == '*' && source[i+1] == '/' {
				return i + 2, nil
			}
			i++
		}
		return 0, fmt.Errorf("unterminated comment")
	default:
		return start, nil
	}
}

type scanner struct {
	source string
	pos    int
}

func scan(source string) ([]Token, error) {
	s := &scanner{source: source}
	tokens := make([]Token, 0, 8)
	for {
		if err := s.skipSpaceAndComments(); err != nil {
			return nil, err
		}
		if s.done() {
			break
		}
		token, err := s.next()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return append(tokens, Token{Kind: TokenEOF, Offset: s.pos}), nil
}

func (s *scanner) skipSpaceAndComments() error {
	for !s.done() {
		r, width := utf8.DecodeRuneInString(s.source[s.pos:])
		if unicode.IsSpace(r) {
			s.pos += width
			continue
		}
		if r != '/' {
			return nil
		}
		next, err := skipComment(s.source, s.pos)
		if err != nil {
			return err
		}
		if next == s.pos {
			return nil
		}
		s.pos = next
	}
	return nil
}

func (s *scanner) next() (Token, error) {
	start := s.pos
	r, width := utf8.DecodeRuneInString(s.source[s.pos:])
	switch r {
	case '+':
		s.pos += width
		if s.peek() == '+' {
			s.pos++
			return Token{Kind: TokenInc, Lexeme: "++", Offset: start}, nil
		}
		return Token{Kind: TokenPlus, Lexeme: "+", Offset: start}, nil
	case '-':
		s.pos += width
		if s.peek() == '-' {
			s.pos++
			return Token{Kind: TokenDec, Lexeme: "--", Offset: start}, nil
		}
		return Token{Kind: TokenMinus, Lexeme: "-", Offset: start}, nil
	case '*':
		s.pos += width
		return Token{Kind: TokenStar, Lexeme: "*", Offset: start}, nil
	case '/':
		s.pos += width
		return Token{Kind: TokenSlash, Lexeme: "/", Offset: start}, nil
	case '%':
		s.pos += width
		return Token{Kind: TokenPercent, Lexeme: "%", Offset: start}, nil
	case '=':
		s.pos += width
		switch s.peek() {
		case '=':
			s.pos++
			return Token{Kind: TokenEq, Lexeme: "==", Offset: start}, nil
		case '>':
			s.pos++
			return Token{Kind: TokenArrow, Lexeme: "=>", Offset: start}, nil
		default:
			return Token{Kind: TokenAssign, Lexeme: "=", Offset: start}, nil
		}
	case '!':
		s.pos += width
		if s.peek() == '=' {
			s.pos++
			return Token{Kind: TokenNe, Lexeme: "!=", Offset: start}, nil
		}
		return Token{Kind: TokenNot, Lexeme: "!", Offset: start}, nil
	case '<':
		s.pos += width
		if s.peek() == '=' {
			s.pos++
			return Token{Kind: TokenLe, Lexeme: "<=", Offset: start}, nil
		}
		return Token{Kind: TokenLt, Lexeme: "<", Offset: start}, nil
	case '>':
		s.pos += width
		if s.peek() == '=' {
			s.pos++
			return Token{Kind: TokenGe, Lexeme: ">=", Offset: start}, nil
		}
		return Token{Kind: TokenGt, Lexeme: ">", Offset: start}, nil
	case '&':
		s.pos += width
		if s.peek() != '&' {
			return Token{}, fmt.Errorf("unexpected character %q", "&")
		}
		s.pos++
		return Token{Kind: TokenAnd, Lexeme: "&&", Offset: start}, nil
	case '|':
		s.pos += width
		if s.peek() != '|' {
			return Token{}, fmt.Errorf("unexpected character %q", "|")
		}
		s.pos++
		return Token{Kind: TokenOr, Lexeme: "||", Offset: start}, nil
	case '.':
		if s.peekAt(1) >= '0' && s.peekAt(1) <= '9' {
			return s.scanNumber()
		}
		s.pos += width
		return Token{Kind: TokenDot, Lexeme: ".", Offset: start}, nil
	case ',':
		s.pos += width
		return Token{Kind: TokenComma, Lexeme: ",", Offset: start}, nil
	case ':':
		s.pos += width
		return Token{Kind: TokenColon, Lexeme: ":", Offset: start}, nil
	case '?':
		// `?.` is one token. Lexing it as `?` then `.` would leave the parser
		// unable to tell a null-conditional access from a ternary whose first
		// arm begins with a member access.
		if s.peekAt(1) == '.' {
			s.pos += 2
			return Token{Kind: TokenQuestionDot, Lexeme: "?.", Offset: start}, nil
		}
		if s.peekAt(1) == '[' {
			s.pos += 2
			return Token{Kind: TokenQuestionBracket, Lexeme: "?[", Offset: start}, nil
		}
		if s.peekAt(1) == '?' {
			s.pos += 2
			return Token{Kind: TokenCoalesce, Lexeme: "??", Offset: start}, nil
		}
		s.pos += width
		return Token{Kind: TokenQuestion, Lexeme: "?", Offset: start}, nil
	case '(':
		s.pos += width
		return Token{Kind: TokenLParen, Lexeme: "(", Offset: start}, nil
	case ')':
		s.pos += width
		return Token{Kind: TokenRParen, Lexeme: ")", Offset: start}, nil
	case '[':
		s.pos += width
		return Token{Kind: TokenLBracket, Lexeme: "[", Offset: start}, nil
	case ']':
		s.pos += width
		return Token{Kind: TokenRBracket, Lexeme: "]", Offset: start}, nil
	case '{':
		s.pos += width
		return Token{Kind: TokenLBrace, Lexeme: "{", Offset: start}, nil
	case '}':
		s.pos += width
		return Token{Kind: TokenRBrace, Lexeme: "}", Offset: start}, nil
	case ';':
		s.pos += width
		return Token{Kind: TokenSemicolon, Lexeme: ";", Offset: start}, nil
	case '"', '\'':
		return s.scanString(byte(r), false)
	case '@':
		if s.peekAt(1) == '"' {
			s.pos++
			return s.scanString('"', true)
		}
		return Token{}, fmt.Errorf("unexpected character %q", "@")
	case '$':
		if s.peekAt(1) == '"' {
			return s.scanInterpolated()
		}
		return Token{}, fmt.Errorf("unexpected character %q", "$")
	default:
		if r >= '0' && r <= '9' {
			return s.scanNumber()
		}
		if r == '_' || unicode.IsLetter(r) {
			return s.scanIdent()
		}
		return Token{}, fmt.Errorf("unexpected character %q", string(r))
	}
}

func (s *scanner) scanIdent() (Token, error) {
	start := s.pos
	for !s.done() {
		r, width := utf8.DecodeRuneInString(s.source[s.pos:])
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			break
		}
		s.pos += width
	}
	lexeme := s.source[start:s.pos]
	token := Token{Kind: TokenIdent, Lexeme: lexeme, Offset: start}
	switch keywords[lexeme] {
	case TokenTrue:
		token.Kind, token.Literal = TokenTrue, Bool(true)
	case TokenFalse:
		token.Kind, token.Literal = TokenFalse, Bool(false)
	case TokenNull:
		token.Kind, token.Literal = TokenNull, Null()
	case TokenReturn, TokenIf, TokenElse, TokenVar, TokenNew:
		token.Kind = keywords[lexeme]
	}
	return token, nil
}

func (s *scanner) scanNumber() (Token, error) {
	start := s.pos
	isDouble := false
	if s.peek() == '.' {
		isDouble = true
		s.pos++
	}
	for s.peek() >= '0' && s.peek() <= '9' {
		s.pos++
	}
	if s.peek() == '.' && s.peekAt(1) >= '0' && s.peekAt(1) <= '9' {
		isDouble = true
		s.pos++
		for s.peek() >= '0' && s.peek() <= '9' {
			s.pos++
		}
	}
	if s.peek() == 'e' || s.peek() == 'E' {
		isDouble = true
		s.pos++
		if s.peek() == '+' || s.peek() == '-' {
			s.pos++
		}
		if s.peek() < '0' || s.peek() > '9' {
			return Token{}, fmt.Errorf("invalid number exponent")
		}
		for s.peek() >= '0' && s.peek() <= '9' {
			s.pos++
		}
	}
	lexeme := s.source[start:s.pos]
	if isDouble {
		value, _ := strconv.ParseFloat(lexeme, 64)
		return Token{Kind: TokenNumber, Lexeme: lexeme, Literal: Double(value), Offset: start}, nil
	}
	value, err := strconv.ParseInt(lexeme, 10, 64)
	if err != nil {
		return Token{}, fmt.Errorf("invalid number")
	}
	return Token{Kind: TokenNumber, Lexeme: lexeme, Literal: Int(value), Offset: start}, nil
}

func (s *scanner) scanString(quote byte, verbatim bool) (Token, error) {
	start := s.pos
	s.pos++
	var body strings.Builder
	for !s.done() {
		r, width := utf8.DecodeRuneInString(s.source[s.pos:])
		if r == rune(quote) {
			if verbatim && s.peekAt(1) == '"' {
				body.WriteByte('"')
				s.pos += 2
				continue
			}
			s.pos += width
			lexeme := s.source[start:s.pos]
			return Token{Kind: TokenString, Lexeme: lexeme, Literal: String(body.String()), Offset: start}, nil
		}
		if verbatim {
			body.WriteString(s.source[s.pos : s.pos+width])
			s.pos += width
			continue
		}
		if r == '\n' || r == '\r' {
			return Token{}, fmt.Errorf("unterminated string")
		}
		if r != '\\' {
			body.WriteString(s.source[s.pos : s.pos+width])
			s.pos += width
			continue
		}
		s.pos += width
		if s.done() {
			return Token{}, fmt.Errorf("unterminated string")
		}
		escaped, width, err := decodeEscape(s.source[s.pos:])
		if err != nil {
			return Token{}, err
		}
		body.WriteString(escaped)
		s.pos += width
	}
	return Token{}, fmt.Errorf("unterminated string")
}

// interpolationPart is one piece of a `$"..."` string: either literal text or
// the source of a hole.
type interpolationPart struct {
	text   string
	isHole bool
}

// splitInterpolation reads the body of an interpolated string -- everything
// after `$"` -- and returns its parts with the index of the closing quote.
//
// ONE function serves the lexer, which needs the end, and the parser, which
// needs the parts. Two scanners over the same syntax would be two chances to
// disagree about where a hole stops.
//
// A hole may contain strings, and those strings may contain braces and quotes:
// Microsoft's own policies write `$"{x.ToString("R")}"` and
// `$"{context.Variables["state"]}"`. So a hole is scanned with brace depth AND
// string awareness, not by finding the next `}`.
func splitInterpolation(body string) ([]interpolationPart, int, error) {
	var parts []interpolationPart
	var literal strings.Builder
	flush := func() {
		if literal.Len() > 0 {
			parts = append(parts, interpolationPart{text: literal.String()})
			literal.Reset()
		}
	}
	for i := 0; i < len(body); {
		switch body[i] {
		case '"':
			flush()
			return parts, i, nil
		// `{{` and `}}` are literal braces. APIM's own named values are already
		// substituted into the document before this runs, so a doubled brace
		// here is C#'s escape and nothing else.
		case '{':
			if i+1 < len(body) && body[i+1] == '{' {
				literal.WriteByte('{')
				i += 2
				continue
			}
			closeAt, err := matchingCloser(body, i, '{', '}')
			if err != nil {
				return nil, 0, fmt.Errorf("unclosed hole in an interpolated string")
			}
			flush()
			parts = append(parts, interpolationPart{text: body[i+1 : closeAt], isHole: true})
			i = closeAt + 1
		case '}':
			if i+1 < len(body) && body[i+1] == '}' {
				literal.WriteByte('}')
				i += 2
				continue
			}
			return nil, 0, fmt.Errorf("unmatched '}' in an interpolated string")
		case '\\':
			if i+1 >= len(body) {
				return nil, 0, fmt.Errorf("unterminated string")
			}
			escaped, width, err := decodeEscape(body[i+1:])
			if err != nil {
				return nil, 0, err
			}
			literal.WriteString(escaped)
			i += 1 + width
		case '\n', '\r':
			return nil, 0, fmt.Errorf("unterminated string")
		default:
			literal.WriteByte(body[i])
			i++
		}
	}
	return nil, 0, fmt.Errorf("unterminated string")
}

func (s *scanner) scanInterpolated() (Token, error) {
	start := s.pos
	body := s.source[s.pos+2:]
	_, closeAt, err := splitInterpolation(body)
	if err != nil {
		return Token{}, err
	}
	s.pos = s.pos + 2 + closeAt + 1
	return Token{Kind: TokenInterpolated, Lexeme: s.source[start:s.pos], Offset: start}, nil
}

func decodeEscape(source string) (string, int, error) {
	r, width := utf8.DecodeRuneInString(source)
	switch r {
	case 'n':
		return "\n", width, nil
	case 'r':
		return "\r", width, nil
	case 't':
		return "\t", width, nil
	case '0':
		return "\x00", width, nil
	case '\\', '"', '\'':
		return string(r), width, nil
	case 'u':
		if len(source) < 5 {
			return "", 0, fmt.Errorf("invalid unicode escape")
		}
		value, err := strconv.ParseUint(source[1:5], 16, 16)
		if err != nil {
			return "", 0, fmt.Errorf("invalid unicode escape")
		}
		return string(rune(value)), 5, nil
	default:
		return "", 0, fmt.Errorf("invalid escape \\%s", string(r))
	}
}

func (s *scanner) done() bool { return s.pos >= len(s.source) }

func (s *scanner) peek() byte {
	if s.done() {
		return 0
	}
	return s.source[s.pos]
}

func (s *scanner) peekAt(offset int) byte {
	index := s.pos + offset
	if index >= len(s.source) {
		return 0
	}
	return s.source[index]
}
