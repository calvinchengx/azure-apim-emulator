package expression

import (
	"strings"
	"testing"
)

// DateTime, DateTimeOffset and Guid, ranked by measuring the corpus:
// `Guid.NewGuid` (15), `Guid.Parse` (12), `DateTime.UtcNow` (8),
// `DateTimeOffset.UtcNow` (6), and `ToString` (19 across the three).
func TestTimeAndGuid(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct{ source, want string }{
		{`@(new DateTime(1970, 1, 1).ToString("yyyy-MM-ddTHH:mm:ssZ"))`, "1970-01-01T00:00:00Z"},
		{`@(new DateTime(2020, 3, 4, 5, 6, 7).ToString("yyyy-MM-dd HH:mm:ss"))`, "2020-03-04 05:06:07"},
		// "R" is always GMT, never the zone's own name. Go's RFC1123 prints
		// "UTC", and an HTTP Date header carrying that is not a valid HTTP-date.
		{`@(new DateTime(2020, 1, 2).ToString("R"))`, "Thu, 02 Jan 2020 00:00:00 GMT"},
		{`@(new DateTime(2020, 1, 2).ToString("r"))`, "Thu, 02 Jan 2020 00:00:00 GMT"},
		{`@(new DateTime(2020, 1, 2).ToString("u"))`, "2020-01-02 00:00:00Z"},
		{`@(new DateTime(2020, 1, 2).ToString("s"))`, "2020-01-02T00:00:00"},
		{`@(new DateTime(2020, 1, 2).ToString())`, "01/02/2020 00:00:00"},
		// Custom patterns, including the single-letter widths.
		{`@(new DateTime(2020, 3, 4).ToString("M/d/yy"))`, "3/4/20"},
		// The single-letter width tokens, which drop the leading zero.
		{`@(new DateTime(2020, 3, 4, 5, 6, 7).ToString("H:m:s"))`, "5:6:7"},
		{`@(new DateTime(2020, 3, 4, 5, 6, 7).ToString("HH:mm:ss"))`, "05:06:07"},
		// A time renders as text when interpolated, without an explicit
		// ToString, which is how a policy usually puts one in a header.
		{`@($"{new DateTime(2020, 1, 2)}")`, "01/02/2020 00:00:00"},
		{`@($"{new DateTimeOffset(new DateTime(2020, 1, 2))}")`, "01/02/2020 00:00:00"},
		{`@($"{Guid.Empty}")`, "00000000-0000-0000-0000-000000000000"},
		{`@(new DateTime(2020, 3, 4).AddDays(1).ToString("yyyy-MM-dd"))`, "2020-03-05"},
		{`@(new DateTime(2020, 3, 4).AddSeconds(3600).ToString("HH:mm:ss"))`, "01:00:00"},
		{`@(new DateTime(2020, 3, 4).AddMinutes(90).ToString("HH:mm"))`, "01:30"},
		{`@(new DateTime(2020, 3, 4).Year)`, "2020"},
		{`@(new DateTime(2020, 3, 4).Month)`, "3"},
		{`@(new DateTime(2020, 3, 4).Day)`, "4"},
		// DateTimeOffset round-trips through unix time.
		{`@(DateTimeOffset.FromUnixTimeSeconds(86400).ToUnixTimeSeconds())`, "86400"},
		{`@(DateTimeOffset.FromUnixTimeMilliseconds(1500).ToUnixTimeMilliseconds())`, "1500"},
		{`@(DateTimeOffset.FromUnixTimeSeconds(0).ToString("yyyy-MM-dd"))`, "1970-01-01"},
		{`@(new DateTimeOffset(new DateTime(2020, 1, 2)).ToUnixTimeSeconds())`, "1577923200"},
		// AddSeconds keeps the type it was called on.
		{`@(DateTimeOffset.FromUnixTimeSeconds(0).AddSeconds(60).ToUnixTimeSeconds())`, "60"},
		// A guid renders in .NET's canonical form, and parses back.
		{`@(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e").ToString())`, "0f8fad5b-d9cb-469f-a165-70867728950e"},
		{`@(Guid.Parse("{0f8fad5b-d9cb-469f-a165-70867728950e}").ToString())`, "0f8fad5b-d9cb-469f-a165-70867728950e"},
		{`@(Guid.Parse("0f8fad5bd9cb469fa16570867728950e").ToString())`, "0f8fad5b-d9cb-469f-a165-70867728950e"},
		{`@(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e").ToString("N"))`, "0f8fad5bd9cb469fa16570867728950e"},
		{`@(Guid.Empty.ToString())`, "00000000-0000-0000-0000-000000000000"},
		// ToByteArray uses .NET's MIXED-endian layout, so the round trip holds.
		// Returning the textual order would round-trip wrongly, and the corpus
		// does exactly this round trip.
		{`@(new Guid(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e").ToByteArray()).ToString())`, "0f8fad5b-d9cb-469f-a165-70867728950e"},
		{`@(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e").ToByteArray()[0])`, "91"},
		{`@(Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e").ToByteArray().Length)`, "16"},
		{`@(new Guid("0f8fad5b-d9cb-469f-a165-70867728950e").ToString())`, "0f8fad5b-d9cb-469f-a165-70867728950e"},
	} {
		got, err := EvalEnv(test.source, env)
		if err != nil {
			t.Fatalf("%s: %v", test.source, err)
		}
		if got.String() != test.want {
			t.Fatalf("%s = %q, want %q", test.source, got.String(), test.want)
		}
	}
	// NewGuid is random and version 4, so only its shape is asserted.
	first, err := EvalEnv(`@(Guid.NewGuid().ToString())`, env)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvalEnv(`@(Guid.NewGuid().ToString())`, env)
	if err != nil {
		t.Fatal(err)
	}
	if first.String() == second.String() {
		t.Fatal("NewGuid answered the same value twice")
	}
	if len(first.String()) != 36 || first.String()[14] != '4' {
		t.Fatalf("NewGuid = %q, which is not a version 4 guid", first.String())
	}
	// The clock is the REAL one, as it is in Azure: a policy stamping an expiry
	// needs the time now, not the time the request arrived.
	if got, err := EvalEnv(`@(DateTime.UtcNow.Year > 2000)`, env); err != nil || !got.Truthy() {
		t.Fatalf("UtcNow year = %v, %v", got.Truthy(), err)
	}
	if got, err := EvalEnv(`@(DateTimeOffset.UtcNow.ToUnixTimeSeconds() > 0)`, env); err != nil || !got.Truthy() {
		t.Fatalf("DateTimeOffset.UtcNow = %v, %v", got.Truthy(), err)
	}
	if _, err := EvalEnv(`@(DateTime.Now.Year)`, env); err != nil {
		t.Fatalf("DateTime.Now: %v", err)
	}
	if _, err := EvalEnv(`@(DateTimeOffset.Now.ToUnixTimeSeconds())`, env); err != nil {
		t.Fatalf("DateTimeOffset.Now: %v", err)
	}
	if _, err := EvalEnv(`@(DateTime.UtcNow.Ticks > 0)`, env); err != nil {
		t.Fatalf("Ticks: %v", err)
	}
	// Ticks count from year 1, not the unix epoch. The epoch's own tick count
	// is a published constant, so it pins the origin rather than trusting the
	// arithmetic that produced it.
	if epoch, err := EvalEnv(`@(new DateTime(1970, 1, 1).Ticks)`, env); err != nil || epoch.String() != "621355968000000000" {
		t.Fatalf("epoch ticks = %q, %v", epoch.String(), err)
	}
	ticks, err := EvalEnv(`@(new DateTime(2020, 1, 2).Ticks)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ticks.String() != "637135200000000000" {
		t.Fatalf("ticks = %q", ticks.String())
	}
	if _, err := EvalEnv(`@(DateTimeOffset.FromUnixTimeSeconds(0).UtcDateTime.Year)`, env); err != nil {
		t.Fatalf("UtcDateTime: %v", err)
	}
	if _, err := EvalEnv(`@(DateTimeOffset.FromUnixTimeSeconds(0).DateTime.Year)`, env); err != nil {
		t.Fatalf("DateTime member: %v", err)
	}
	if _, err := EvalEnv(`@(new DateTime(2020, 1, 2).AddHours(1).ToString("HH"))`, env); err != nil {
		t.Fatalf("AddHours: %v", err)
	}
	if _, err := EvalEnv(`@(new DateTime(2020, 1, 2).AddMilliseconds(1).ToString("fff"))`, env); err != nil {
		t.Fatalf("AddMilliseconds: %v", err)
	}
	if got, err := EvalEnv(`@(new DateTime(2020, 1, 2).ToString("o"))`, env); err != nil || !strings.HasPrefix(got.String(), "2020-01-02T") {
		t.Fatalf("round-trip format = %q, %v", got.String(), err)
	}
	if got, err := EvalEnv(`@(new DateTime(2020, 1, 2).ToString("yy"))`, env); err != nil || got.String() != "20" {
		t.Fatalf("two-digit year = %q, %v", got.String(), err)
	}
}

func TestTimeAndGuidRefusals(t *testing.T) {
	env := Bind(Context{})
	for _, test := range []struct{ source, contains string }{
		{`@(DateTime.Nonexistent)`, "unknown member"},
		{`@(DateTimeOffset.Nonexistent)`, "unknown member"},
		{`@(Guid.Nonexistent)`, "unknown member"},
		{`@(DateTime.UtcNow.Nonexistent)`, "unknown member"},
		{`@(DateTimeOffset.UtcNow.Nonexistent)`, "unknown member"},
		{`@(Guid.NewGuid().Nonexistent)`, "unknown member"},
		{`@(Guid.Parse("not-a-guid"))`, "is not a guid"},
		{`@(Guid.Parse("0f8fad5b-d9cb-469f-a165-7086772895zz"))`, "is not a guid"},
		{`@(Guid.Parse())`, "takes one string"},
		{`@(Guid.NewGuid(1))`, "takes no arguments"},
		{`@(Guid.NewGuid().ToByteArray(1))`, "takes no arguments"},
		{`@(new Guid(1))`, "byte array or a string"},
		{`@(new Guid(Encoding.UTF8.GetBytes("short")))`, "needs 16 bytes"},
		{`@(new DateTime(2020))`, "year, month and day"},
		{`@(new DateTime("a", "b", "c"))`, "takes numbers"},
		{`@(new DateTimeOffset(1))`, "takes a DateTime"},
		{`@(new DateTimeOffset())`, "takes one DateTime"},
		{`@(DateTimeOffset.FromUnixTimeSeconds("x"))`, "takes one number"},
		{`@(DateTimeOffset.FromUnixTimeSeconds())`, "takes one number"},
		{`@(DateTime.UtcNow.AddSeconds())`, "takes one number"},
		{`@(DateTime.UtcNow.AddSeconds("x"))`, "takes one number"},
		{`@(DateTime.UtcNow.ToString(1))`, "takes a format string"},
		{`@(DateTime.UtcNow.ToString("a", "b"))`, "at most one format"},
		{`@(Guid.Empty.ToString("a", "b"))`, "at most one format"},
		{`@(DateTimeOffset.UtcNow.ToUnixTimeSeconds(1))`, "takes no arguments"},
		{`@(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(1))`, "takes no arguments"},
	} {
		if _, err := EvalEnv(test.source, env); err == nil {
			t.Fatalf("accepted %s", test.source)
		} else if !strings.Contains(err.Error(), test.contains) {
			t.Fatalf("%s failed with %q, want %q", test.source, err, test.contains)
		}
	}
}
