package expression

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DateTime, DateTimeOffset and Guid.
//
// Ranked by measuring the corpus: `Guid.NewGuid` (15), `Guid.Parse` (12),
// `DateTime.UtcNow` (8), `DateTimeOffset.UtcNow` (6), then `ToString` (19
// across the three), `AddSeconds` (7), `ToByteArray` (3) and
// `ToUnixTimeMilliseconds` (2).
//
// These read the REAL clock, as they do in Azure. A policy stamping a token
// with an expiry needs the time now, not the time the request arrived, so
// `context.Timestamp` is a different thing and stays separate.

type dateTimeStaticHost struct{}

func (dateTimeStaticHost) member(name string) (Value, error) {
	switch name {
	case "UtcNow":
		return Object(dateTimeHost{at: time.Now().UTC()}), nil
	case "Now":
		return Object(dateTimeHost{at: time.Now()}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on DateTime", name)
	}
}

type dateTimeOffsetStaticHost struct{}

func (dateTimeOffsetStaticHost) member(name string) (Value, error) {
	switch name {
	case "UtcNow":
		return Object(dateTimeOffsetHost{at: time.Now().UTC()}), nil
	case "Now":
		return Object(dateTimeOffsetHost{at: time.Now()}), nil
	case "FromUnixTimeSeconds", "FromUnixTimeMilliseconds":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("%s takes one number", name)
			}
			number, ok := args[0].AsNumber()
			if !ok {
				return Null(), fmt.Errorf("%s takes one number", name)
			}
			if name == "FromUnixTimeSeconds" {
				return Object(dateTimeOffsetHost{at: time.Unix(int64(number), 0).UTC()}), nil
			}
			return Object(dateTimeOffsetHost{at: time.UnixMilli(int64(number)).UTC()}), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on DateTimeOffset", name)
	}
}

type dateTimeHost struct {
	at time.Time
}

func (d dateTimeHost) member(name string) (Value, error) {
	shared := commonTimeHost{at: d.at, rebuild: func(at time.Time) Value {
		return Object(dateTimeHost{at: at})
	}}
	if value, err := shared.member(name); !errors.Is(err, errNotCommonTimeMember) {
		return value, err
	}
	switch name {
	case "Ticks":
		// .NET counts 100-nanosecond intervals from year 1, not from the unix
		// epoch. Computed from SECONDS rather than by subtracting times: a
		// time.Duration is int64 nanoseconds, the span from year 1 to now
		// overflows it, and the saturated result is a plausible-looking number
		// that is simply wrong.
		return Int((d.at.Unix()+secondsFromYearOneToEpoch)*ticksPerSecond + int64(d.at.Nanosecond())/100), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a DateTime", name)
	}
}

func (d dateTimeHost) String() string { return formatDotNet(d.at, "") }

type dateTimeOffsetHost struct {
	at time.Time
}

func (d dateTimeOffsetHost) member(name string) (Value, error) {
	shared := commonTimeHost{at: d.at, rebuild: func(at time.Time) Value {
		return Object(dateTimeOffsetHost{at: at})
	}}
	if value, err := shared.member(name); !errors.Is(err, errNotCommonTimeMember) {
		return value, err
	}
	switch name {
	case "ToUnixTimeSeconds":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("ToUnixTimeSeconds takes no arguments")
			}
			return Int(d.at.Unix()), nil
		}}), nil
	case "ToUnixTimeMilliseconds":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("ToUnixTimeMilliseconds takes no arguments")
			}
			return Int(d.at.UnixMilli()), nil
		}}), nil
	case "UtcDateTime", "DateTime":
		return Object(dateTimeHost{at: d.at.UTC()}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a DateTimeOffset", name)
	}
}

func (d dateTimeOffsetHost) String() string { return formatDotNet(d.at, "") }

const (
	// secondsFromYearOneToEpoch is the gap between .NET's tick origin, midnight
	// on 1 January of year 1, and the unix epoch.
	secondsFromYearOneToEpoch = 62135596800
	ticksPerSecond            = 10000000
)

// commonTimeHost carries what DateTime and DateTimeOffset share.
//
// It is a HOST with a `member` method rather than a helper function so the
// allowlist drift scan can see these cases: the scan reads member methods, and
// a shared function would leave a dozen members ungated on both types. The
// rebuild function keeps `AddSeconds` returning the type it was called on
// rather than collapsing one into the other.
type commonTimeHost struct {
	at      time.Time
	rebuild func(time.Time) Value
}

// errNotCommonTimeMember lets a caller fall through to its own members.
var errNotCommonTimeMember = errors.New("not a shared time member")

func (h commonTimeHost) member(name string) (Value, error) {
	at, rebuild := h.at, h.rebuild
	add := func(unit time.Duration) (Value, error) {
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 {
				return Null(), fmt.Errorf("%s takes one number", name)
			}
			number, ok := args[0].AsNumber()
			if !ok {
				return Null(), fmt.Errorf("%s takes one number", name)
			}
			return rebuild(at.Add(time.Duration(number * float64(unit)))), nil
		}}), nil
	}
	switch name {
	case "AddSeconds":
		return add(time.Second)
	case "AddMinutes":
		return add(time.Minute)
	case "AddHours":
		return add(time.Hour)
	case "AddDays":
		return add(24 * time.Hour)
	case "AddMilliseconds":
		return add(time.Millisecond)
	case "Year":
		return Int(int64(at.Year())), nil
	case "Month":
		return Int(int64(at.Month())), nil
	case "Day":
		return Int(int64(at.Day())), nil
	case "ToString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) > 1 {
				return Null(), fmt.Errorf("ToString takes at most one format")
			}
			format := ""
			if len(args) == 1 {
				if args[0].kind != KindString {
					return Null(), fmt.Errorf("ToString takes a format string")
				}
				format = args[0].str
			}
			return String(formatDotNet(at, format)), nil
		}}), nil
	default:
		return Null(), errNotCommonTimeMember
	}
}

// formatDotNet renders a time the way .NET's format strings do.
//
// The pattern is walked and translated directly rather than mapped onto a Go
// layout, because Go's layout treats sequences like `Z` and `2006` as magic and
// a C# pattern containing them as LITERALS would come out wrong.
func formatDotNet(at time.Time, format string) string {
	switch format {
	case "R", "r":
		// Always "GMT", never the zone's own name. Go's RFC1123 prints "UTC"
		// for a UTC time, and an HTTP Date header carrying that is not a valid
		// HTTP-date -- which is precisely what this format is used to build.
		return at.UTC().Format("Mon, 02 Jan 2006 15:04:05") + " GMT"
	case "u":
		return at.UTC().Format("2006-01-02 15:04:05") + "Z"
	case "o", "O":
		return at.Format(time.RFC3339Nano)
	case "s":
		return at.Format("2006-01-02T15:04:05")
	case "":
		// .NET's parameterless ToString is culture-dependent. This evaluator
		// has no culture, so it uses the invariant general pattern and says so
		// rather than picking a locale nobody asked for.
		return at.Format("01/02/2006 15:04:05")
	}
	var out strings.Builder
	for i := 0; i < len(format); {
		run := 1
		for i+run < len(format) && format[i+run] == format[i] {
			run++
		}
		token := format[i : i+run]
		switch token {
		case "yyyy":
			out.WriteString(strconv.Itoa(at.Year()))
		case "yy":
			out.WriteString(fmt.Sprintf("%02d", at.Year()%100))
		case "MM":
			out.WriteString(fmt.Sprintf("%02d", int(at.Month())))
		case "M":
			out.WriteString(strconv.Itoa(int(at.Month())))
		case "dd":
			out.WriteString(fmt.Sprintf("%02d", at.Day()))
		case "d":
			out.WriteString(strconv.Itoa(at.Day()))
		case "HH":
			out.WriteString(fmt.Sprintf("%02d", at.Hour()))
		case "H":
			out.WriteString(strconv.Itoa(at.Hour()))
		case "mm":
			out.WriteString(fmt.Sprintf("%02d", at.Minute()))
		case "m":
			out.WriteString(strconv.Itoa(at.Minute()))
		case "ss":
			out.WriteString(fmt.Sprintf("%02d", at.Second()))
		case "s":
			out.WriteString(strconv.Itoa(at.Second()))
		case "fff":
			out.WriteString(fmt.Sprintf("%03d", at.Nanosecond()/1e6))
		default:
			// Anything unrecognised is a literal, which is what .NET does with
			// the `T` and `Z` in `yyyy-MM-ddTHH:mm:ssZ`.
			out.WriteString(token)
		}
		i += run
	}
	return out.String()
}

type guidStaticHost struct{}

func (guidStaticHost) member(name string) (Value, error) {
	switch name {
	case "NewGuid":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("NewGuid takes no arguments")
			}
			var data [16]byte
			// crypto/rand.Read is documented never to fail as of Go 1.24, so
			// there is no error branch to write. One would be code nothing can
			// run, which is worse than its absence.
			_, _ = rand.Read(data[:])
			// Version 4, variant 1, as .NET's Guid.NewGuid produces.
			data[6] = (data[6] & 0x0f) | 0x40
			data[8] = (data[8] & 0x3f) | 0x80
			return Object(guidHost{data: data}), nil
		}}), nil
	case "Parse":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 1 || args[0].kind != KindString {
				return Null(), fmt.Errorf("Parse takes one string")
			}
			return parseGuid(args[0].str)
		}}), nil
	case "Empty":
		return Object(guidHost{}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on Guid", name)
	}
}

func parseGuid(text string) (Value, error) {
	trimmed := strings.Trim(strings.TrimSpace(text), "{}()")
	stripped := strings.ReplaceAll(trimmed, "-", "")
	if len(stripped) != 32 {
		return Null(), fmt.Errorf("%q is not a guid", text)
	}
	raw, err := hex.DecodeString(stripped)
	if err != nil {
		return Null(), fmt.Errorf("%q is not a guid", text)
	}
	var data [16]byte
	copy(data[:], raw)
	return Object(guidHost{data: data}), nil
}

type guidHost struct {
	data [16]byte
}

func (g guidHost) member(name string) (Value, error) {
	switch name {
	case "ToString":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) > 1 {
				return Null(), fmt.Errorf("ToString takes at most one format")
			}
			if len(args) == 1 && args[0].kind == KindString && args[0].str == "N" {
				return String(strings.ReplaceAll(g.String(), "-", "")), nil
			}
			return String(g.String()), nil
		}}), nil
	case "ToByteArray":
		return Object(funcValue{fn: func(args []Value) (Value, error) {
			if len(args) != 0 {
				return Null(), fmt.Errorf("ToByteArray takes no arguments")
			}
			return Object(bytesHost{data: g.bytes()}), nil
		}}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a Guid", name)
	}
}

func (g guidHost) String() string {
	text := hex.EncodeToString(g.data[:])
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

// bytes is .NET's Guid.ToByteArray layout, which is MIXED-endian: the first
// three fields are little-endian and the last eight bytes are not. Returning
// the textual order would round-trip wrongly through `new Guid(bytes)`, and the
// corpus does exactly that round trip.
func (g guidHost) bytes() []byte {
	out := make([]byte, 16)
	copy(out, g.data[:])
	out[0], out[1], out[2], out[3] = g.data[3], g.data[2], g.data[1], g.data[0]
	out[4], out[5] = g.data[5], g.data[4]
	out[6], out[7] = g.data[7], g.data[6]
	return out
}

// guidFromBytes reverses that layout, so `new Guid(g.ToByteArray())` is g.
func guidFromBytes(raw []byte) (Value, error) {
	if len(raw) != 16 {
		return Null(), fmt.Errorf("a guid needs 16 bytes, got %d", len(raw))
	}
	var data [16]byte
	copy(data[:], raw)
	data[0], data[1], data[2], data[3] = raw[3], raw[2], raw[1], raw[0]
	data[4], data[5] = raw[5], raw[4]
	data[6], data[7] = raw[7], raw[6]
	return Object(guidHost{data: data}), nil
}
