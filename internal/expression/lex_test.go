package expression

import (
	"strings"
	"testing"
)

func kinds(tokens []Token) []TokenKind {
	result := make([]TokenKind, len(tokens))
	for i, token := range tokens {
		result[i] = token.Kind
	}
	return result
}

func TestLexWrappersAndOperators(t *testing.T) {
	tokens, form, err := Lex(" @( context.Request.Method == \"GET\" && !false ) ")
	if err != nil || form != FormExpression {
		t.Fatalf("expression form = %d %v", form, err)
	}
	if want := []TokenKind{TokenIdent, TokenDot, TokenIdent, TokenDot, TokenIdent, TokenEq, TokenString, TokenAnd, TokenNot, TokenFalse, TokenEOF}; !equalKinds(kinds(tokens), want) {
		t.Fatalf("expression tokens = %v", kinds(tokens))
	}
	if tokens[6].Literal.String() != "GET" || tokens[9].Literal.String() != "False" {
		t.Fatalf("literals = %+v", tokens)
	}

	block, form, err := Lex("@{ if (true) { var x = 1; return x; } else { return null; } }")
	if err != nil || form != FormBlock {
		t.Fatalf("block form = %d %v", form, err)
	}
	if want := []TokenKind{TokenIf, TokenLParen, TokenTrue, TokenRParen, TokenLBrace, TokenVar, TokenIdent, TokenAssign, TokenNumber, TokenSemicolon, TokenReturn, TokenIdent, TokenSemicolon, TokenRBrace, TokenElse, TokenLBrace, TokenReturn, TokenNull, TokenSemicolon, TokenRBrace, TokenEOF}; !equalKinds(kinds(block), want) {
		t.Fatalf("block tokens = %v", kinds(block))
	}

	// `?.` is ONE token now. It used to lex as `?` then `.`, which left the
	// parser unable to tell a null-conditional access from a ternary.
	bare, form, err := Lex("items[0]?.Name")
	if err != nil || form != FormBare || !equalKinds(kinds(bare), []TokenKind{TokenIdent, TokenLBracket, TokenNumber, TokenRBracket, TokenQuestionDot, TokenIdent, TokenEOF}) {
		t.Fatalf("bare = %v %d %v", kinds(bare), form, err)
	}
	// A `?` that does not touch a `.` is still a ternary's.
	ternary, _, err := Lex("a ? b : c")
	if err != nil || !equalKinds(kinds(ternary), []TokenKind{TokenIdent, TokenQuestion, TokenIdent, TokenColon, TokenIdent, TokenEOF}) {
		t.Fatalf("ternary = %v %v", kinds(ternary), err)
	}

	ops, _, err := Lex("a + b - c * d / e % f < g <= h > i >= j != k || m => n ++ -- , : new")
	if err != nil {
		t.Fatal(err)
	}
	if want := []TokenKind{TokenIdent, TokenPlus, TokenIdent, TokenMinus, TokenIdent, TokenStar, TokenIdent, TokenSlash, TokenIdent, TokenPercent, TokenIdent, TokenLt, TokenIdent, TokenLe, TokenIdent, TokenGt, TokenIdent, TokenGe, TokenIdent, TokenNe, TokenIdent, TokenOr, TokenIdent, TokenArrow, TokenIdent, TokenInc, TokenDec, TokenComma, TokenColon, TokenNew, TokenEOF}; !equalKinds(kinds(ops), want) {
		t.Fatalf("ops = %v", kinds(ops))
	}
}

func TestLexNumbersStringsAndComments(t *testing.T) {
	tokens, _, err := Lex("@(1 + .5 + 2.25 + 1e2 + 1E-1 + 1e+3 + 8/2)")
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0].Literal.Interface() != int64(1) || tokens[2].Literal.Interface() != 0.5 || tokens[4].Literal.Interface() != 2.25 {
		t.Fatalf("numbers = %+v", tokens)
	}
	if tokens[6].Literal.Interface() != 100.0 || tokens[8].Literal.Interface() != 0.1 || tokens[10].Literal.Interface() != 1000.0 {
		t.Fatalf("exponents = %+v", tokens)
	}

	text, _, err := Lex(`@("a\n\r\t\0\\\"\u0041" + @"say ""hi""")`)
	if err != nil {
		t.Fatal(err)
	}
	if text[0].Literal.String() != "a\n\r\t\x00\\\"A" || text[2].Literal.String() != `say "hi"` {
		t.Fatalf("strings = %q %q", text[0].Literal.String(), text[2].Literal.String())
	}
	single, _, err := Lex("@('GET' + 'it\\'s')")
	if err != nil || single[0].Literal.String() != "GET" || single[2].Literal.String() != "it's" {
		t.Fatalf("single quotes = %+v %v", single, err)
	}

	commented, _, err := Lex("@(1 /* inner ) still */ + 2 // line\n + 3)")
	if err != nil || !equalKinds(kinds(commented), []TokenKind{TokenNumber, TokenPlus, TokenNumber, TokenPlus, TokenNumber, TokenEOF}) {
		t.Fatalf("comments = %v %v", kinds(commented), err)
	}
	slash, _, err := Lex("1 / 2 /")
	if err != nil || slash[1].Kind != TokenSlash || slash[3].Kind != TokenSlash {
		t.Fatalf("slashes = %v %v", kinds(slash), err)
	}
	if _, _, err := Lex("9223372036854775808"); err == nil {
		t.Fatal("overflow accepted")
	}
	if _, _, err := Lex("1e"); err == nil {
		t.Fatal("bare exponent accepted")
	}
	if _, _, err := Lex("1e+"); err == nil {
		t.Fatal("signed bare exponent accepted")
	}
}

func TestLexWrapperAndScanErrors(t *testing.T) {
	for _, source := range []string{
		"@(1",
		"@{ return 1;",
		`@("abc`,
		`@("abc\`,
		"@(\"a\nb\")",
		"@(1 /* open",
		`@( @"open`,
		"@(1) extra",
		"@{return 1;} extra",
		"@foo",
		"1 & 2",
		"1 | 2",
		"#",
		"@bare",
		`"unterminated`,
		"\"\n\"",
		`"abc\`,
		`'unterminated`,
		`'\q'`,
		`"\q"`,
		`"\u12"`,
		`"\uZZZZ"`,
		`@"open`,
		"1 /* open",
		`@( @x )`,
		"@( /",
		"1 @ 2",
	} {
		if _, _, err := Lex(source); err == nil {
			t.Fatalf("accepted %q", source)
		}
	}
	empty, form, err := Lex("@()")
	if err != nil || form != FormExpression || len(empty) != 1 || empty[0].Kind != TokenEOF {
		t.Fatalf("empty expression = %+v %d %v", empty, form, err)
	}
	ident, _, err := Lex("item2")
	if err != nil || ident[0].Kind != TokenIdent || ident[0].Lexeme != "item2" {
		t.Fatalf("ident = %+v %v", ident, err)
	}
	greek, _, err := Lex("α")
	if err != nil || greek[0].Lexeme != "α" {
		t.Fatalf("unicode ident = %+v %v", greek, err)
	}
	dot, _, err := Lex("name.")
	if err != nil || dot[1].Kind != TokenDot {
		t.Fatalf("trailing dot = %+v %v", dot, err)
	}
}

func equalKinds(got, want []TokenKind) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestLexStringWithCloserInLiteral(t *testing.T) {
	tokens, form, err := Lex(`@("a)b" + @"c}d")`)
	if err != nil || form != FormExpression || tokens[0].Literal.String() != "a)b" || tokens[2].Literal.String() != "c}d" {
		t.Fatalf("closer in string = %+v %d %v", tokens, form, err)
	}
	if !strings.Contains(tokens[0].Lexeme, `"`) {
		t.Fatal("string lexeme lost quotes")
	}
	quoted, form, err := Lex("@('a)b')")
	if err != nil || form != FormExpression || quoted[0].Literal.String() != "a)b" {
		t.Fatalf("closer in single-quoted string = %+v %d %v", quoted, form, err)
	}
}
