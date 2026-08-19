package expression

import (
	"math"
	"strings"
	"testing"
)

type stringerValue struct{}

func (stringerValue) String() string { return "host" }

func TestValueConstructorsAndConversions(t *testing.T) {
	if !Null().IsNull() || Null().Kind() != KindNull || Null().Interface() != nil || Null().Truthy() || Null().String() != "" {
		t.Fatalf("null = %+v", Null())
	}
	if truth, ok := Null().AsBool(); ok || truth {
		t.Fatal("null AsBool succeeded")
	}
	if number, ok := Null().AsNumber(); ok || number != 0 || Null().IsNumeric() {
		t.Fatal("null AsNumber succeeded")
	}

	if !Bool(true).Truthy() || Bool(true).String() != "True" || Bool(true).Interface() != true {
		t.Fatalf("true = %+v", Bool(true))
	}
	if Bool(false).Truthy() || Bool(false).String() != "False" || Bool(false).Interface() != false {
		t.Fatalf("false = %+v", Bool(false))
	}
	if truth, ok := Bool(true).AsBool(); !ok || !truth {
		t.Fatal("true AsBool failed")
	}
	if truth, ok := Bool(false).AsBool(); !ok || truth {
		t.Fatal("false AsBool failed")
	}

	if Int(42).Interface() != int64(42) || Int(42).String() != "42" || !Int(42).IsNumeric() {
		t.Fatalf("int = %+v", Int(42))
	}
	if number, ok := Int(7).AsNumber(); !ok || number != 7 {
		t.Fatal("int AsNumber failed")
	}

	if Double(1.5).Interface() != 1.5 || Double(1.5).String() != "1.5" {
		t.Fatalf("double = %+v", Double(1.5))
	}
	if number, ok := Double(2.25).AsNumber(); !ok || number != 2.25 {
		t.Fatal("double AsNumber failed")
	}
	if String("text").Interface() != "text" || String("text").String() != "text" || String("text").Truthy() {
		t.Fatalf("string = %+v", String("text"))
	}

	if Object(nil).Kind() != KindNull {
		t.Fatal("nil object was not null")
	}
	if Object(map[string]int{"n": 1}).Interface().(map[string]int)["n"] != 1 || Object(map[string]int{"n": 1}).String() != "" {
		t.Fatal("object interface/string failed")
	}
	if Object(stringerValue{}).String() != "host" {
		t.Fatal("stringer object failed")
	}
}

func TestFormatDoubleAndEquality(t *testing.T) {
	if formatDouble(math.NaN()) != "NaN" || formatDouble(math.Inf(1)) != "Infinity" || formatDouble(math.Inf(-1)) != "-Infinity" {
		t.Fatalf("formatDouble specials = %q %q %q", formatDouble(math.NaN()), formatDouble(math.Inf(1)), formatDouble(math.Inf(-1)))
	}
	if !equal(Null(), Null()) || equal(Null(), Bool(false)) || equal(Bool(true), String("true")) {
		t.Fatal("null/bool equality failed")
	}
	if !equal(Int(2), Double(2)) || equal(Int(2), Double(2.5)) || !equal(Bool(true), Bool(true)) || equal(Bool(true), Bool(false)) {
		t.Fatal("numeric/bool equality failed")
	}
	if !equal(String("a"), String("a")) || equal(String("a"), String("b")) || !equal(Object("same"), Object("same")) || equal(Object("left"), Object("right")) {
		t.Fatal("string/object equality failed")
	}
}

// Indexing a null says so. It used to share the message a number gets, which
// sent an author looking for a type problem they did not have.
func TestIndexOnNullSaysSo(t *testing.T) {
	env := Bind(Context{})
	if _, err := EvalEnv(`@(context.Variables["absent"]["k"])`, env); err == nil {
		t.Fatal("indexing null was accepted")
	} else if !strings.Contains(err.Error(), "index on null") {
		t.Fatalf("indexing null said %q", err)
	}
	// A value that is present but not indexable keeps its own message.
	if _, err := EvalEnv(`@(1["k"])`, env); err == nil {
		t.Fatal("indexing a number was accepted")
	} else if !strings.Contains(err.Error(), "not indexable") {
		t.Fatalf("indexing a number said %q", err)
	}
}
