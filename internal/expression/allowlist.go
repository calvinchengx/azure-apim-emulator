package expression

import "sort"

// MemberStatus is the ledger state of one documented expression member.
type MemberStatus string

const (
	// MemberBound is implemented on the binder and fails closed for other names.
	MemberBound MemberStatus = "bound"
	// MemberPlanned is a documented APIM member that is still unknown at runtime.
	MemberPlanned MemberStatus = "planned"
	// MemberFramework is a member of a .NET type Microsoft's reference lists as
	// available to a policy, but whose members that reference does not
	// enumerate. `context.Request.Certificate` is an X509Certificate2: the type
	// really is available in a tenant, so this is a stronger claim than an
	// extension, but the member list is OUR reading of .NET rather than of an
	// APIM document, so it is a weaker one than `bound`.
	MemberFramework MemberStatus = "framework"
	// MemberExtension is a member THIS EMULATOR answers and Azure does not
	// document. It is a divergence in the permissive direction: a policy using
	// it works here and fails in a tenant. Naming it is the point -- an
	// extension listed as `bound` would inflate the ledger and hide the trap.
	MemberExtension MemberStatus = "extension"
)

// Member is one type/member pair in the public expression allowlist.
type Member struct {
	Type   string       `json:"type"`
	Name   string       `json:"name"`
	Status MemberStatus `json:"status"`
}

// Allowlist is the binder's type/member ledger. Bound entries must match the
// host switches; planned entries stay unknown until a later slice implements
// them. Adding a host member without listing it here fails the table test.
func Allowlist() []Member {
	return []Member{
		{Type: "context", Name: "Api", Status: MemberBound},
		{Type: "context", Name: "Backend", Status: MemberBound},
		{Type: "context", Name: "Deployment", Status: MemberBound},
		{Type: "context", Name: "Elapsed", Status: MemberBound},
		{Type: "context", Name: "GraphQL", Status: MemberBound},
		{Type: "context", Name: "LastError", Status: MemberBound},
		{Type: "context", Name: "Operation", Status: MemberBound},
		{Type: "context", Name: "Product", Status: MemberBound},
		{Type: "context", Name: "Request", Status: MemberBound},
		{Type: "context", Name: "RequestId", Status: MemberBound},
		{Type: "context", Name: "Response", Status: MemberBound},
		{Type: "context", Name: "Subscription", Status: MemberBound},
		{Type: "context", Name: "Timestamp", Status: MemberBound},
		{Type: "context", Name: "Trace", Status: MemberBound},
		{Type: "context", Name: "Tracing", Status: MemberBound},
		{Type: "context", Name: "User", Status: MemberBound},
		{Type: "context", Name: "Variables", Status: MemberBound},
		{Type: "Api", Name: "Id", Status: MemberBound},
		{Type: "Api", Name: "IsCurrentRevision", Status: MemberBound},
		{Type: "Api", Name: "Name", Status: MemberBound},
		{Type: "Api", Name: "Path", Status: MemberBound},
		{Type: "Api", Name: "Protocols", Status: MemberBound},
		{Type: "Api", Name: "Revision", Status: MemberBound},
		{Type: "Api", Name: "ServiceUrl", Status: MemberBound},
		{Type: "Api", Name: "Version", Status: MemberBound},
		{Type: "Deployment", Name: "Certificates", Status: MemberBound},
		{Type: "Deployment", Name: "Gateway", Status: MemberBound},
		{Type: "Deployment", Name: "GatewayId", Status: MemberBound},
		{Type: "Deployment", Name: "Region", Status: MemberBound},
		{Type: "Deployment", Name: "ServiceId", Status: MemberBound},
		{Type: "Deployment", Name: "ServiceName", Status: MemberBound},
		{Type: "Gateway", Name: "Id", Status: MemberBound},
		{Type: "Gateway", Name: "InstanceId", Status: MemberBound},
		{Type: "Gateway", Name: "IsManaged", Status: MemberBound},
		{Type: "LastError", Name: "PolicyId", Status: MemberBound},
		{Type: "LastError", Name: "Message", Status: MemberBound},
		{Type: "LastError", Name: "Reason", Status: MemberBound},
		{Type: "LastError", Name: "Scope", Status: MemberBound},
		{Type: "LastError", Name: "Section", Status: MemberBound},
		{Type: "LastError", Name: "Source", Status: MemberBound},
		{Type: "Operation", Name: "Id", Status: MemberBound},
		{Type: "Operation", Name: "Method", Status: MemberBound},
		{Type: "Operation", Name: "Name", Status: MemberBound},
		{Type: "Operation", Name: "UrlTemplate", Status: MemberBound},
		{Type: "Product", Name: "Apis", Status: MemberBound},
		{Type: "Product", Name: "ApprovalRequired", Status: MemberBound},
		{Type: "Product", Name: "Groups", Status: MemberBound},
		{Type: "Product", Name: "Id", Status: MemberBound},
		{Type: "Product", Name: "Name", Status: MemberBound},
		{Type: "Product", Name: "State", Status: MemberBound},
		{Type: "Product", Name: "SubscriptionRequired", Status: MemberBound},
		{Type: "Product", Name: "SubscriptionLimit", Status: MemberBound},
		{Type: "Product", Name: "SubscriptionsLimit", Status: MemberBound},
		{Type: "Request", Name: "Body", Status: MemberBound},
		{Type: "Request", Name: "Certificate", Status: MemberBound},
		{Type: "Request", Name: "Headers", Status: MemberBound},
		{Type: "Request", Name: "IpAddress", Status: MemberBound},
		{Type: "Request", Name: "MatchedParameters", Status: MemberBound},
		{Type: "Request", Name: "Method", Status: MemberBound},
		{Type: "Request", Name: "OriginalUrl", Status: MemberBound},
		{Type: "Request", Name: "Url", Status: MemberBound},
		{Type: "Response", Name: "Body", Status: MemberBound},
		{Type: "Response", Name: "Headers", Status: MemberBound},
		{Type: "Response", Name: "StatusCode", Status: MemberBound},
		{Type: "Response", Name: "StatusReason", Status: MemberBound},
		{Type: "Subscription", Name: "CreatedDate", Status: MemberBound},
		{Type: "Subscription", Name: "EndDate", Status: MemberBound},
		{Type: "Subscription", Name: "Id", Status: MemberBound},
		{Type: "Subscription", Name: "Key", Status: MemberBound},
		{Type: "Subscription", Name: "Name", Status: MemberBound},
		{Type: "Subscription", Name: "PrimaryKey", Status: MemberBound},
		{Type: "Subscription", Name: "SecondaryKey", Status: MemberBound},
		{Type: "Subscription", Name: "StartDate", Status: MemberBound},
		{Type: "User", Name: "Email", Status: MemberBound},
		{Type: "User", Name: "FirstName", Status: MemberBound},
		{Type: "User", Name: "Groups", Status: MemberBound},
		{Type: "User", Name: "Id", Status: MemberBound},
		{Type: "User", Name: "Identities", Status: MemberBound},
		{Type: "User", Name: "LastName", Status: MemberBound},
		{Type: "User", Name: "Note", Status: MemberBound},
		{Type: "User", Name: "RegistrationDate", Status: MemberBound},
		{Type: "Group", Name: "Id", Status: MemberBound},
		{Type: "Group", Name: "Name", Status: MemberBound},
		{Type: "UserIdentity", Name: "Id", Status: MemberBound},
		{Type: "UserIdentity", Name: "Provider", Status: MemberBound},
		{Type: "Certificate", Name: "Issuer", Status: MemberFramework},
		{Type: "Certificate", Name: "NotAfter", Status: MemberFramework},
		{Type: "Certificate", Name: "NotBefore", Status: MemberFramework},
		{Type: "Certificate", Name: "SerialNumber", Status: MemberFramework},
		{Type: "Certificate", Name: "Subject", Status: MemberFramework},
		{Type: "Certificate", Name: "Thumbprint", Status: MemberFramework},
		{Type: "Certificate", Name: "Verify", Status: MemberFramework},
		{Type: "Certificate", Name: "VerifyNoRevocation", Status: MemberBound},
		{Type: "Url", Name: "Host", Status: MemberBound},
		{Type: "Url", Name: "Path", Status: MemberBound},
		{Type: "Url", Name: "Port", Status: MemberBound},
		{Type: "Url", Name: "Query", Status: MemberBound},
		{Type: "Url", Name: "QueryString", Status: MemberBound},
		{Type: "Url", Name: "Scheme", Status: MemberBound},
		{Type: "Backend", Name: "Id", Status: MemberBound},
		{Type: "Backend", Name: "Type", Status: MemberBound},
		{Type: "Random", Name: "Next", Status: MemberFramework},
		{Type: "Uri", Name: "AbsolutePath", Status: MemberFramework},
		{Type: "Uri", Name: "AbsoluteUri", Status: MemberFramework},
		{Type: "Uri", Name: "Host", Status: MemberFramework},
		{Type: "Uri", Name: "Scheme", Status: MemberFramework},
		{Type: "Uri", Name: "Query", Status: MemberFramework},
		{Type: "Uri", Name: "Port", Status: MemberFramework},
		{Type: "JProperty", Name: "Name", Status: MemberFramework},
		{Type: "JProperty", Name: "Value", Status: MemberFramework},
		{Type: "JObject", Name: "Count", Status: MemberFramework},
		{Type: "JObject", Name: "ContainsKey", Status: MemberFramework},
		{Type: "JObject", Name: "ToString", Status: MemberFramework},
		{Type: "Body", Name: "As", Status: MemberBound},
		{Type: "Body", Name: "AsFormUrlEncodedContent", Status: MemberBound},
		{Type: "GraphQL", Name: "GraphQLArguments", Status: MemberBound},
		{Type: "GraphQL", Name: "Parent", Status: MemberBound},
		{Type: "Arguments", Name: "ContainsKey", Status: MemberBound},
		{Type: "Arguments", Name: "Count", Status: MemberBound},
		{Type: "Authorization", Name: "AccessToken", Status: MemberBound},
		{Type: "Authorization", Name: "ClientId", Status: MemberBound},
		{Type: "Authorization", Name: "Scopes", Status: MemberBound},
		{Type: "Authorization", Name: "ExpiresIn", Status: MemberBound},
		{Type: "Headers", Name: "ContainsKey", Status: MemberFramework},
		{Type: "Headers", Name: "Count", Status: MemberFramework},
		{Type: "Headers", Name: "Get", Status: MemberBound},
		{Type: "Headers", Name: "GetValueOrDefault", Status: MemberBound},
		{Type: "Certificates", Name: "ContainsKey", Status: MemberBound},
		{Type: "Certificates", Name: "Count", Status: MemberBound},
		{Type: "Variables", Name: "ContainsKey", Status: MemberBound},
		{Type: "Variables", Name: "GetValueOrDefault", Status: MemberBound},
		{Type: "Query", Name: "GetValueOrDefault", Status: MemberBound},
		{Type: "Query", Name: "ContainsKey", Status: MemberFramework},
		{Type: "Query", Name: "Count", Status: MemberFramework},
		{Type: "value", Name: "ToString", Status: MemberBound},
		{Type: "string", Name: "Split", Status: MemberFramework},
		{Type: "string", Name: "Trim", Status: MemberFramework},
		{Type: "string", Name: "TrimStart", Status: MemberFramework},
		{Type: "string", Name: "TrimEnd", Status: MemberFramework},
		{Type: "string", Name: "ToLower", Status: MemberFramework},
		{Type: "string", Name: "ToUpper", Status: MemberFramework},
		{Type: "string", Name: "StartsWith", Status: MemberFramework},
		{Type: "string", Name: "EndsWith", Status: MemberFramework},
		{Type: "string", Name: "Contains", Status: MemberFramework},
		{Type: "string", Name: "Equals", Status: MemberFramework},
		{Type: "string", Name: "Replace", Status: MemberFramework},
		{Type: "string", Name: "Substring", Status: MemberFramework},
		{Type: "string", Name: "IndexOf", Status: MemberFramework},
		{Type: "string", Name: "GetHashCode", Status: MemberFramework},
		{Type: "StringComparison", Name: "Ordinal", Status: MemberFramework},
		{Type: "StringComparison", Name: "OrdinalIgnoreCase", Status: MemberFramework},
		{Type: "StringComparison", Name: "InvariantCulture", Status: MemberFramework},
		{Type: "StringComparison", Name: "InvariantCultureIgnoreCase", Status: MemberFramework},
		{Type: "StringComparison", Name: "CurrentCulture", Status: MemberFramework},
		{Type: "StringComparison", Name: "CurrentCultureIgnoreCase", Status: MemberFramework},
		{Type: "Convert", Name: "FromBase64String", Status: MemberFramework},
		{Type: "Convert", Name: "ToBase64String", Status: MemberFramework},
		{Type: "Convert", Name: "ToString", Status: MemberFramework},
		{Type: "Encoding", Name: "UTF8", Status: MemberFramework},
		{Type: "UTF8", Name: "GetBytes", Status: MemberFramework},
		{Type: "UTF8", Name: "GetString", Status: MemberFramework},
		{Type: "Uri", Name: "EscapeDataString", Status: MemberFramework},
		{Type: "Uri", Name: "UnescapeDataString", Status: MemberFramework},
		{Type: "string", Name: "Empty", Status: MemberFramework},
		{Type: "string", Name: "IsNullOrEmpty", Status: MemberFramework},
		{Type: "string", Name: "IsNullOrWhiteSpace", Status: MemberFramework},
		{Type: "string", Name: "Concat", Status: MemberFramework},
		{Type: "string", Name: "Join", Status: MemberFramework},
		{Type: "string", Name: "Format", Status: MemberFramework},
		{Type: "int", Name: "Parse", Status: MemberFramework},
		{Type: "int", Name: "MaxValue", Status: MemberFramework},
		{Type: "int", Name: "MinValue", Status: MemberFramework},
		{Type: "byte[]", Name: "Length", Status: MemberFramework},
		{Type: "string", Name: "Length", Status: MemberFramework},
		{Type: "string", Name: "AsJwt", Status: MemberBound},
		{Type: "string", Name: "AsBasic", Status: MemberBound},
		{Type: "Jwt", Name: "Id", Status: MemberBound},
		{Type: "Jwt", Name: "Algorithm", Status: MemberBound},
		{Type: "Jwt", Name: "Issuer", Status: MemberBound},
		{Type: "Jwt", Name: "Subject", Status: MemberBound},
		{Type: "Jwt", Name: "Type", Status: MemberBound},
		{Type: "Jwt", Name: "Audiences", Status: MemberBound},
		{Type: "Jwt", Name: "Claims", Status: MemberBound},
		{Type: "Jwt", Name: "ExpirationTime", Status: MemberBound},
		{Type: "Jwt", Name: "NotBefore", Status: MemberBound},
		{Type: "Jwt", Name: "IssuedAt", Status: MemberBound},
		{Type: "Claims", Name: "GetValueOrDefault", Status: MemberBound},
		{Type: "Claims", Name: "ContainsKey", Status: MemberFramework},
		{Type: "Claims", Name: "Count", Status: MemberFramework},
		{Type: "BasicAuthCredentials", Name: "Username", Status: MemberBound},
		{Type: "BasicAuthCredentials", Name: "Password", Status: MemberBound},
	}
}

// frameworkTypeOf names the .NET type a `framework` allowlist entry reads.
//
// The gate uses it to check Microsoft's reference actually lists that type. An
// entry claiming framework status for a type nobody lists would be an extension
// wearing a stronger label.
func frameworkTypeOf(typ string) (string, bool) {
	switch typ {
	case "Certificate":
		return "System.Security.Cryptography.X509Certificates.X509Certificate2", true
	case "string":
		return "System.String", true
	case "Convert":
		return "System.Convert", true
	case "Encoding", "UTF8":
		return "System.Text.Encoding", true
	case "int":
		return "System.Int32", true
	case "byte[]":
		return "System.Byte", true
	case "StringComparison":
		return "System.StringComparison", true
	case "Random":
		return "System.Random", true
	case "Uri":
		return "System.Uri", true
	case "JObject":
		return "Newtonsoft.Json.Linq.JObject", true
	case "JProperty":
		return "Newtonsoft.Json.Linq.JProperty", true
	case "Query", "Claims", "Headers":
		// Microsoft types `IUrl.Query` and `Jwt.Claims` as
		// IReadOnlyDictionary<string, string[]>,
		// so its dictionary members come from .NET rather than from an APIM
		// document.
		return "System.Collections.Generic.IReadOnlyDictionary<TKey, TValue>", true
	}
	return "", false
}

// Inventory is the full ledger: what this emulator implements, plus every
// documented member it does not, as `planned`.
//
// Planned rows are COMPUTED rather than written down. Hand-maintaining a list of
// what somebody else documents is exactly the drift this package already paid
// for once: a documented member nobody noticed simply never got a row. Deriving
// them means a member Microsoft adds becomes a planned row the moment the
// vendored source is refreshed, with nobody needing to notice.
func Inventory() []Member {
	implemented := map[string]map[string]bool{}
	members := []Member{}
	for _, member := range Allowlist() {
		if implemented[member.Type] == nil {
			implemented[member.Type] = map[string]bool{}
		}
		implemented[member.Type][member.Name] = true
		members = append(members, member)
	}
	for _, member := range Documented() {
		if implemented[member.Type][member.Name] {
			continue
		}
		members = append(members, Member{Type: member.Type, Name: member.Name, Status: MemberPlanned})
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].Type != members[j].Type {
			return members[i].Type < members[j].Type
		}
		return members[i].Name < members[j].Name
	})
	return members
}
