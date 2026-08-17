package expression

// MemberStatus is the ledger state of one documented expression member.
type MemberStatus string

const (
	// MemberBound is implemented on the binder and fails closed for other names.
	MemberBound MemberStatus = "bound"
	// MemberPlanned is a documented APIM member that is still unknown at runtime.
	MemberPlanned MemberStatus = "planned"
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
		{Type: "context", Name: "Request", Status: MemberBound},
		{Type: "context", Name: "Response", Status: MemberBound},
		{Type: "context", Name: "Variables", Status: MemberBound},
		{Type: "context", Name: "LastError", Status: MemberBound},
		{Type: "context", Name: "Api", Status: MemberBound},
		{Type: "context", Name: "Operation", Status: MemberBound},
		{Type: "context", Name: "Product", Status: MemberBound},
		{Type: "context", Name: "Subscription", Status: MemberBound},
		{Type: "context", Name: "User", Status: MemberBound},
		{Type: "context", Name: "Deployment", Status: MemberBound},
		{Type: "context", Name: "GraphQL", Status: MemberBound},
		{Type: "GraphQL", Name: "Arguments", Status: MemberBound},
		{Type: "GraphQL", Name: "Parent", Status: MemberBound},
		{Type: "Arguments", Name: "ContainsKey", Status: MemberBound},
		{Type: "Arguments", Name: "Count", Status: MemberBound},
		{Type: "Authorization", Name: "AccessToken", Status: MemberBound},
		{Type: "Authorization", Name: "ClientId", Status: MemberBound},
		{Type: "Authorization", Name: "Scopes", Status: MemberBound},
		{Type: "Authorization", Name: "ExpiresIn", Status: MemberBound},
		{Type: "Request", Name: "Method", Status: MemberBound},
		{Type: "Request", Name: "Url", Status: MemberBound},
		{Type: "Request", Name: "URL", Status: MemberBound},
		{Type: "Request", Name: "Headers", Status: MemberBound},
		{Type: "Request", Name: "IpAddress", Status: MemberBound},
		{Type: "Request", Name: "Body", Status: MemberBound},
		{Type: "Request", Name: "OriginalUrl", Status: MemberPlanned},
		{Type: "Response", Name: "StatusCode", Status: MemberBound},
		{Type: "Response", Name: "StatusReason", Status: MemberBound},
		{Type: "Response", Name: "Headers", Status: MemberBound},
		{Type: "Response", Name: "Body", Status: MemberBound},
		{Type: "LastError", Name: "Message", Status: MemberBound},
		{Type: "LastError", Name: "Reason", Status: MemberPlanned},
		{Type: "Url", Name: "Path", Status: MemberBound},
		{Type: "Url", Name: "Host", Status: MemberBound},
		{Type: "Url", Name: "Scheme", Status: MemberBound},
		{Type: "Url", Name: "Query", Status: MemberBound},
		{Type: "Url", Name: "QueryString", Status: MemberBound},
		{Type: "Url", Name: "Port", Status: MemberBound},
		{Type: "Headers", Name: "Get", Status: MemberBound},
		{Type: "Headers", Name: "GetValueOrDefault", Status: MemberBound},
		{Type: "Variables", Name: "ContainsKey", Status: MemberBound},
		{Type: "Body", Name: "AsString", Status: MemberBound},
		{Type: "Body", Name: "AsJObject", Status: MemberPlanned},
		{Type: "Body", Name: "AsJson", Status: MemberPlanned},
		{Type: "Api", Name: "Id", Status: MemberBound},
		{Type: "Api", Name: "Name", Status: MemberBound},
		{Type: "Api", Name: "Path", Status: MemberBound},
		{Type: "Api", Name: "Revision", Status: MemberPlanned},
		{Type: "Operation", Name: "Id", Status: MemberBound},
		{Type: "Operation", Name: "Name", Status: MemberBound},
		{Type: "Operation", Name: "Method", Status: MemberBound},
		{Type: "Operation", Name: "UrlTemplate", Status: MemberBound},
		{Type: "Product", Name: "Id", Status: MemberBound},
		{Type: "Product", Name: "Name", Status: MemberBound},
		{Type: "Product", Name: "Apis", Status: MemberPlanned},
		{Type: "Subscription", Name: "Id", Status: MemberBound},
		{Type: "Subscription", Name: "Name", Status: MemberBound},
		{Type: "Subscription", Name: "Key", Status: MemberPlanned},
		{Type: "User", Name: "Id", Status: MemberBound},
		{Type: "User", Name: "Name", Status: MemberBound},
		{Type: "User", Name: "Email", Status: MemberPlanned},
		{Type: "Deployment", Name: "ServiceName", Status: MemberBound},
		{Type: "Deployment", Name: "Region", Status: MemberBound},
		{Type: "Deployment", Name: "Gateway", Status: MemberPlanned},
		{Type: "value", Name: "ToString", Status: MemberBound},
		{Type: "string", Name: "Length", Status: MemberBound},
	}
}
