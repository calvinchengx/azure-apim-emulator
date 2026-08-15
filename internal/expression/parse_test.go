package expression

import (
	"math"
	"testing"
)

func TestEvalLiteralsOperatorsAndGrouping(t *testing.T) {
	cases := []struct {
		source string
		want   any
	}{
		{"@(true)", true},
		{"@(false)", false},
		{"@(null)", nil},
		{"@(42)", int64(42)},
		{`@("hi")`, "hi"},
		{"1 + 2 * 3", int64(7)},
		{"@( (1 + 2) * 3 )", int64(9)},
		{"@(8 - 3 - 2)", int64(3)},
		{"@(-1 + +2)", int64(1)},
		{"@(-(-3))", int64(3)},
		{"@(+2.5)", 2.5},
		{"@(-2.5)", -2.5},
		{"@(!false)", true},
		{"@(!true)", false},
		{`@("a" + "b")`, "ab"},
		{`@("a" + null)`, "a"},
		{`@(1 + "x")`, "1x"},
		{`@(true + "x")`, "Truex"},
		{"@(1 + 2.5)", 3.5},
		{"@(3.5 - 1.0)", 2.5},
		{"@(2.0 * 3.0)", 6.0},
		{"@(5 / 2)", int64(2)},
		{"@(5 % 2)", int64(1)},
		{"@(7.5 / 2.5)", 3.0},
		{"@(5.5 % 2.0)", 1.5},
		{"@(1.0 / 0.0)", math.Inf(1)},
		{"@(2.0 % 0.0)", math.NaN()},
		{"@(1 == 1.0)", true},
		{"@(1 != 2)", true},
		{"@(null == null)", true},
		{"@(null != 1)", true},
		{"@(1 < 2)", true},
		{"@(2 <= 2)", true},
		{"@(3 > 2)", true},
		{"@(3 >= 3)", true},
		{`@("a" < "b")`, true},
		{`@("b" > "a")`, true},
		{`@("a" <= "a")`, true},
		{`@("b" >= "a")`, true},
		{"@(true && true)", true},
		{"@(true && false)", false},
		{"@(false || true)", true},
		{"@(false || false)", false},
		{"@(false && (1 / 0))", false},
		{"@(true || (1 / 0))", true},
		{"@(true ? 1 : 2)", int64(1)},
		{"@(false ? 1 : 2)", int64(2)},
		{"@(true ? false ? 1 : 2 : 3)", int64(2)},
	}
	for _, test := range cases {
		got, err := Eval(test.source)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if math.IsNaN(toFloat(test.want)) {
			if number, ok := got.AsNumber(); !ok || !math.IsNaN(number) {
				t.Fatalf("%s = %+v, want NaN", test.source, got)
			}
			continue
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}
}

func TestEvalAndParseErrors(t *testing.T) {
	for _, source := range []string{
		"@(",
		"@()",
		"@{ return 1; }",
		"@(1 2)",
		"@(1 + )",
		"@((1)",
		"@(true ? 1)",
		"@(true ?)",
		"@(true ? ( : 1)",
		"@(false ? 1 : )",
		"@(!)",
		"@( () )",
		"(1",
		"@(context)",
		"@(++)",
		"@(--3)",
		"@(-true)",
		"@(+false)",
		"@(!1)",
		"@(-\"x\")",
		"@(1 + true)",
		"@(1 / 0)",
		"@(1 % 0)",
		"@(1 < true)",
		"@(1 && true)",
		"@(true && 1)",
		"@(1 / 0 && true)",
		"@(true && (1 / 0))",
		"@(1 / 0 || true)",
		"@(1 ? 2 : 3)",
		"@(1 / 0 ? 1 : 2)",
		"@(true ? (1 / 0) : 2)",
		"@(false ? 1 : (1 / 0))",
		"@(-(1 / 0))",
		"@((1 / 0) + 1)",
		"@(1 + (1 / 0))",
		"@(1.)",
		"@(a[)",
		"@(a[1)",
		"@(a[1 2])",
		"@(a(1)",
		"@(a(1 2))",
		"@(a(1,))",
		"@((1 / 0).ToString())",
		"@(true.ToString((1 / 0)))",
		"@((1 / 0)[0])",
	} {
		if _, err := Eval(source); err == nil {
			t.Fatalf("accepted %s", source)
		}
	}
	if _, form, err := Parse("@{ return 1; }"); err == nil || form != FormBlock {
		t.Fatalf("block parse = %d %v", form, err)
	}
	if _, form, err := Parse("@(1 + 2)"); err != nil || form != FormExpression {
		t.Fatalf("expression parse = %d %v", form, err)
	}
}

func TestEvalInternalBranches(t *testing.T) {
	empty := &parser{}
	if empty.peek().Kind != TokenEOF || empty.take().Kind != TokenEOF {
		t.Fatal("empty parser should yield EOF")
	}
	if _, err := (binaryExpr{op: TokenDot, left: literalExpr{value: Int(1)}, right: literalExpr{value: Int(2)}}).eval(nil); err == nil {
		t.Fatal("unsupported operator accepted")
	}
	if _, err := (unaryExpr{op: TokenMinus, x: literalExpr{value: String("x")}}).eval(nil); err == nil {
		t.Fatal("unary minus on string accepted")
	}
	if _, err := (identExpr{name: "x"}).eval(&Env{}); err == nil {
		t.Fatal("empty env identifier accepted")
	}
}

func toFloat(value any) float64 {
	number, ok := value.(float64)
	if !ok {
		return 0
	}
	return number
}
