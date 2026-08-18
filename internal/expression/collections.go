package expression

import "fmt"

// Collections in the expression language.
//
// Azure types these as IEnumerable<T> and a policy usually reaches them through
// LINQ -- `context.User.Groups.Any(g => g.Name == "admin")`. **This parser has
// no lambdas, so no LINQ operator is available**, and a policy written that way
// fails here with an unknown member rather than silently returning false. That
// limit is stated in `docs/parity.md` beside the members, because the members
// themselves are genuinely bound: `Count` and indexing work, and the failure
// mode of the missing part is loud.

// listHost is a read-only sequence of objects.
type listHost struct {
	// items are already-wrapped values, so a list of groups and a list of
	// identities need no separate host each.
	items []Value
	// what names the element type in an error, so an unknown member on a list
	// of groups says so rather than saying "list".
	what string
}

func (l *listHost) member(name string) (Value, error) {
	switch name {
	case "Count":
		return Double(float64(len(l.items))), nil
	case "Any":
		return Object(funcValue{fn: l.any}), nil
	default:
		return Null(), fmt.Errorf("unknown member %s on a collection of %s (Count and Any are the only operators this expression language implements)", name, l.what)
	}
}

// any answers whether any element satisfies the predicate.
//
// The predicate is a lambda, which evaluates to a callable, so this invokes it
// the same way a policy invokes anything else. A predicate that answers with
// something other than a boolean is an ERROR rather than a truthiness test: a
// policy whose predicate returns a string has a bug, and guessing would hide it.
func (l *listHost) any(args []Value) (Value, error) {
	if len(args) != 1 {
		return Null(), fmt.Errorf("Any takes one predicate, as in Any(g => g.Name == \"admin\")")
	}
	for _, item := range l.items {
		got, err := args[0].call([]Value{item})
		if err != nil {
			return Null(), err
		}
		if got.kind != KindBool {
			return Null(), fmt.Errorf("an Any predicate must answer true or false")
		}
		if got.Truthy() {
			return Bool(true), nil
		}
	}
	return Bool(false), nil
}

// index reads one element. Out of range is an error rather than null, because a
// policy indexing past the end has a bug and a null would surface it later as a
// confusing member-access-on-null somewhere else.
func (l *listHost) index(key Value) (Value, error) {
	position, ok := collectionIndex(key)
	if !ok {
		return Null(), fmt.Errorf("a collection of %s is indexed by position", l.what)
	}
	if position < 0 || position >= len(l.items) {
		return Null(), fmt.Errorf("position %d is outside a collection of %d %s", position, len(l.items), l.what)
	}
	return l.items[position], nil
}

// GroupContext is the documented group identity.
type GroupContext struct {
	Id   string
	Name string
}

type groupHost struct {
	ctx GroupContext
}

func (g *groupHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(g.ctx.Id), nil
	case "Name":
		return String(g.ctx.Name), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// UserIdentityContext is one external identity a user signs in with.
type UserIdentityContext struct {
	Id       string
	Provider string
}

type userIdentityHost struct {
	ctx UserIdentityContext
}

func (u *userIdentityHost) member(name string) (Value, error) {
	switch name {
	case "Id":
		return String(u.ctx.Id), nil
	case "Provider":
		return String(u.ctx.Provider), nil
	default:
		return Null(), fmt.Errorf("unknown member %s", name)
	}
}

// groupList wraps groups as a collection value.
func groupList(groups []GroupContext) Value {
	items := make([]Value, 0, len(groups))
	for _, group := range groups {
		items = append(items, Object(&groupHost{ctx: group}))
	}
	return Object(&listHost{items: items, what: "groups"})
}

// identityList wraps identities as a collection value.
func identityList(identities []UserIdentityContext) Value {
	items := make([]Value, 0, len(identities))
	for _, identity := range identities {
		items = append(items, Object(&userIdentityHost{ctx: identity}))
	}
	return Object(&listHost{items: items, what: "identities"})
}

// apiList wraps APIs as a collection value.
func apiList(apis []ApiContext) Value {
	items := make([]Value, 0, len(apis))
	for index := range apis {
		items = append(items, Object(&apiHost{ctx: &apis[index]}))
	}
	return Object(&listHost{items: items, what: "APIs"})
}

// collectionIndex reads a position from either numeric kind.
//
// An integer literal binds as KindInt and arithmetic yields KindDouble, and
// `Groups[0]` is the only way anyone indexes one of these -- accepting just one
// kind refused the common case.
func collectionIndex(key Value) (int, bool) {
	switch key.kind {
	case KindInt:
		return int(key.num), true
	case KindDouble:
		return int(key.dbl), true
	default:
		return 0, false
	}
}

// jsonDocument turns decoded JSON into a value a policy can walk.
//
// Objects and arrays stay indexable rather than collapsing to their text, which
// is the difference between `As<JObject>()` and `As<string>()`. Scalars fall
// through to the same conversion GraphQL arguments use, so a number reads the
// same way in both places.
func jsonDocument(value any) (Value, error) {
	switch typed := value.(type) {
	case map[string]any:
		return Object(&jsonMapHost{values: typed}), nil
	case []any:
		items := make([]Value, 0, len(typed))
		for _, item := range typed {
			converted, err := jsonDocument(item)
			if err != nil {
				return Null(), err
			}
			items = append(items, converted)
		}
		return Object(&listHost{items: items, what: "elements"}), nil
	default:
		return jsonValue(typed)
	}
}
