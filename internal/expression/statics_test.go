package expression

import (
	"strings"
	"testing"
)

// The static types a policy calls into, ranked by MEASURING the corpus:
// `Convert.FromBase64String` leads at 38 references, then `Encoding.UTF8` (26),
// `Convert.ToBase64String` (23), `int.Parse` (20), `string.Empty` (13).
func TestStaticMembers(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct {
		source string
		want   any
	}{
		// The pair the corpus uses most: text in, base64 out and back again.
		{`@(Convert.ToBase64String(Encoding.UTF8.GetBytes("hi")))`, "aGk="},
		{`@(Encoding.UTF8.GetString(Convert.FromBase64String("aGk=")))`, "hi"},
		{`@(Encoding.UTF8.GetBytes("hi").Length)`, int64(2)},
		{`@(Convert.FromBase64String("aGk=")[0])`, int64(104)},
		{`@(Convert.ToString(42))`, "42"},
		{`@(int.Parse("42") + 1)`, int64(43)},
		{`@(int.Parse(" 42 "))`, int64(42)},
		{`@(int.MaxValue)`, int64(2147483647)},
		{`@(string.Empty)`, ""},
		{`@(string.IsNullOrEmpty(""))`, true},
		{`@(string.IsNullOrEmpty("a"))`, false},
		{`@(string.IsNullOrEmpty(context.Variables["absent"]))`, true},
		{`@(string.IsNullOrWhiteSpace("  "))`, true},
		{`@(String.Concat("a", "b", "c"))`, "abc"},
		{`@(string.Join("-", "a", "b"))`, "a-b"},
		{`@(string.Format("{0}-{1}", "a", 2))`, "a-2"},
		// A doubled brace is a literal one, as it is in an interpolated string.
		{`@(string.Format("{{0}}"))`, "{0}"},
		// .NET escapes a space as %20, where a naive query escape gives '+'.
		// A policy building a URL needs the former.
		{`@(Uri.EscapeDataString("a b&c"))`, "a%20b%26c"},
		{`@(Uri.UnescapeDataString("a%20b"))`, "a b"},
		// `String` and `string` are the same type, and policies write both.
		{`@(String.Format("{0}", "x"))`, "x"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.Interface() != test.want {
			t.Fatalf("%s = %#v, want %#v", test.source, got.Interface(), test.want)
		}
	}
}

func TestStaticMemberRefusals(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct{ source, contains string }{
		{`@(Convert.Nonexistent)`, "unknown member"},
		{`@(Convert.FromBase64String("not base64!!"))`, "not base64"},
		{`@(Convert.FromBase64String(1))`, "takes one string"},
		// A byte array is its own type, so encoding anything else reports
		// rather than silently encoding a rendering.
		{`@(Convert.ToBase64String("text"))`, "takes a byte array"},
		{`@(Encoding.UTF8.GetString("text"))`, "takes a byte array"},
		{`@(Convert.ToBase64String())`, "takes one byte array"},
		{`@(Convert.ToString())`, "takes one value"},
		{`@(Encoding.UTF8.GetString())`, "takes one byte array"},
		// Only UTF8 is bound: another encoding fails by name rather than
		// answering UTF-8 bytes labelled as something else.
		{`@(Encoding.ASCII)`, "only UTF8 is implemented"},
		{`@(Encoding.UTF8.Nonexistent)`, "unknown member"},
		{`@(Encoding.UTF8.GetBytes(1))`, "takes one string"},
		{`@(Convert.FromBase64String("aGk=")[9])`, "outside a byte array"},
		{`@(Convert.FromBase64String("aGk=")["x"])`, "indexed by position"},
		{`@(Convert.FromBase64String("aGk=").Nonexistent)`, "unknown member"},
		// .NET throws on a bad parse. Answering zero would send a policy down a
		// branch it never chose.
		{`@(int.Parse("abc"))`, "is not an integer"},
		{`@(int.Parse())`, "takes one value"},
		{`@(int.Nonexistent)`, "unknown member"},
		{`@(string.Nonexistent)`, "unknown member"},
		{`@(string.IsNullOrEmpty())`, "takes one value"},
		{`@(string.IsNullOrWhiteSpace())`, "takes one value"},
		{`@(string.Join(1))`, "a separator and values"},
		{`@(string.Format())`, "takes a format string"},
		{`@(string.Format(1))`, "takes a format string"},
		// Alignment and format specifiers are refused rather than dropped, the
		// same choice interpolated strings make.
		{`@(string.Format("{0,10}", "a"))`, "not implemented"},
		{`@(string.Format("{0:F2}", 1))`, "not implemented"},
		{`@(string.Format("{0}", ))`, "unexpected token"},
		{`@(string.Format("{9}", "a"))`, "has no argument"},
		{`@(string.Format("{0"))`, "unclosed placeholder"},
		{`@(Uri.Nonexistent)`, "unknown member"},
		{`@(Uri.EscapeDataString(1))`, "takes one string"},
		{`@(Uri.UnescapeDataString("%zz"))`, "not escaped"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}
