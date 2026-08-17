package expression

// MemberStatus is the ledger state of one documented expression member.
type MemberStatus string

const (
	// MemberBound is implemented on the binder and fails closed for other names.
	MemberBound MemberStatus = "bound"
	// MemberPlanned is a documented APIM member that is still unknown at runtime.
	MemberPlanned MemberStatus = "planned"
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
		{Type: "context", Name: "Deployment", Status: MemberBound},
		{Type: "context", Name: "Elapsed", Status: MemberPlanned},
		{Type: "context", Name: "GraphQL", Status: MemberBound},
		{Type: "context", Name: "LastError", Status: MemberBound},
		{Type: "context", Name: "Operation", Status: MemberBound},
		{Type: "context", Name: "Product", Status: MemberBound},
		{Type: "context", Name: "Request", Status: MemberBound},
		{Type: "context", Name: "RequestId", Status: MemberPlanned},
		{Type: "context", Name: "Response", Status: MemberBound},
		{Type: "context", Name: "Subscription", Status: MemberBound},
		{Type: "context", Name: "Timestamp", Status: MemberPlanned},
		{Type: "context", Name: "Tracing", Status: MemberPlanned},
		{Type: "context", Name: "User", Status: MemberBound},
		{Type: "context", Name: "Variables", Status: MemberBound},
		{Type: "Api", Name: "Id", Status: MemberBound},
		{Type: "Api", Name: "IsCurrentRevision", Status: MemberPlanned},
		{Type: "Api", Name: "Name", Status: MemberBound},
		{Type: "Api", Name: "Path", Status: MemberBound},
		{Type: "Api", Name: "Revision", Status: MemberPlanned},
		{Type: "Api", Name: "ServiceUrl", Status: MemberPlanned},
		{Type: "Api", Name: "Version", Status: MemberPlanned},
		{Type: "Deployment", Name: "Certificates", Status: MemberPlanned},
		{Type: "Deployment", Name: "Gateway", Status: MemberPlanned},
		{Type: "Deployment", Name: "GatewayId", Status: MemberPlanned},
		{Type: "Deployment", Name: "Region", Status: MemberBound},
		{Type: "Deployment", Name: "ServiceId", Status: MemberPlanned},
		{Type: "Deployment", Name: "ServiceName", Status: MemberBound},
		{Type: "Gateway", Name: "Id", Status: MemberPlanned},
		{Type: "Gateway", Name: "InstanceId", Status: MemberPlanned},
		{Type: "Gateway", Name: "IsManaged", Status: MemberPlanned},
		{Type: "Gateway", Name: "RegionName", Status: MemberPlanned},
		{Type: "LastError", Name: "Element", Status: MemberPlanned},
		{Type: "LastError", Name: "ElementPath", Status: MemberPlanned},
		{Type: "LastError", Name: "Message", Status: MemberBound},
		{Type: "LastError", Name: "Reason", Status: MemberPlanned},
		{Type: "LastError", Name: "Scope", Status: MemberPlanned},
		{Type: "LastError", Name: "Section", Status: MemberPlanned},
		{Type: "LastError", Name: "Source", Status: MemberPlanned},
		{Type: "Operation", Name: "Id", Status: MemberBound},
		{Type: "Operation", Name: "Method", Status: MemberBound},
		{Type: "Operation", Name: "Name", Status: MemberBound},
		{Type: "Operation", Name: "UrlTemplate", Status: MemberBound},
		{Type: "Product", Name: "Apis", Status: MemberPlanned},
		{Type: "Product", Name: "ApprovalRequired", Status: MemberPlanned},
		{Type: "Product", Name: "Groups", Status: MemberPlanned},
		{Type: "Product", Name: "Id", Status: MemberBound},
		{Type: "Product", Name: "Name", Status: MemberBound},
		{Type: "Product", Name: "State", Status: MemberPlanned},
		{Type: "Product", Name: "SubscriptionRequired", Status: MemberPlanned},
		{Type: "Product", Name: "SubscriptionsLimit", Status: MemberPlanned},
		{Type: "Request", Name: "Body", Status: MemberBound},
		{Type: "Request", Name: "Certificate", Status: MemberPlanned},
		{Type: "Request", Name: "Headers", Status: MemberBound},
		{Type: "Request", Name: "IpAddress", Status: MemberBound},
		{Type: "Request", Name: "MatchedParameters", Status: MemberPlanned},
		{Type: "Request", Name: "Method", Status: MemberBound},
		{Type: "Request", Name: "OriginalUrl", Status: MemberPlanned},
		{Type: "Request", Name: "Url", Status: MemberBound},
		{Type: "Response", Name: "Body", Status: MemberBound},
		{Type: "Response", Name: "Headers", Status: MemberBound},
		{Type: "Response", Name: "StatusCode", Status: MemberBound},
		{Type: "Response", Name: "StatusReason", Status: MemberBound},
		{Type: "Subscription", Name: "CreatedDate", Status: MemberPlanned},
		{Type: "Subscription", Name: "EndDate", Status: MemberPlanned},
		{Type: "Subscription", Name: "Id", Status: MemberBound},
		{Type: "Subscription", Name: "Key", Status: MemberPlanned},
		{Type: "Subscription", Name: "Name", Status: MemberBound},
		{Type: "Subscription", Name: "PrimaryKey", Status: MemberPlanned},
		{Type: "Subscription", Name: "SecondaryKey", Status: MemberPlanned},
		{Type: "Subscription", Name: "StartDate", Status: MemberPlanned},
		{Type: "User", Name: "Email", Status: MemberPlanned},
		{Type: "User", Name: "FirstName", Status: MemberPlanned},
		{Type: "User", Name: "Groups", Status: MemberPlanned},
		{Type: "User", Name: "Id", Status: MemberBound},
		{Type: "User", Name: "Identities", Status: MemberPlanned},
		{Type: "User", Name: "LastName", Status: MemberPlanned},
		{Type: "User", Name: "Note", Status: MemberPlanned},
		{Type: "User", Name: "RegistrationDate", Status: MemberPlanned},
		{Type: "Group", Name: "Id", Status: MemberPlanned},
		{Type: "Group", Name: "Name", Status: MemberPlanned},
		{Type: "UserIdentity", Name: "Id", Status: MemberPlanned},
		{Type: "UserIdentity", Name: "Provider", Status: MemberPlanned},
		{Type: "Url", Name: "Host", Status: MemberBound},
		{Type: "Url", Name: "Path", Status: MemberBound},
		{Type: "Url", Name: "Port", Status: MemberBound},
		{Type: "Url", Name: "Query", Status: MemberBound},
		{Type: "Url", Name: "QueryString", Status: MemberBound},
		{Type: "Url", Name: "Scheme", Status: MemberBound},
		{Type: "Body", Name: "As", Status: MemberPlanned},
		{Type: "Body", Name: "AsFormUrlEncodedContent", Status: MemberPlanned},
		{Type: "GraphQL", Name: "Arguments", Status: MemberBound},
		{Type: "GraphQL", Name: "Parent", Status: MemberBound},
		{Type: "Arguments", Name: "ContainsKey", Status: MemberBound},
		{Type: "Arguments", Name: "Count", Status: MemberBound},
		{Type: "Authorization", Name: "AccessToken", Status: MemberBound},
		{Type: "Authorization", Name: "ClientId", Status: MemberBound},
		{Type: "Authorization", Name: "Scopes", Status: MemberBound},
		{Type: "Authorization", Name: "ExpiresIn", Status: MemberBound},
		{Type: "Headers", Name: "Get", Status: MemberBound},
		{Type: "Headers", Name: "GetValueOrDefault", Status: MemberBound},
		{Type: "Variables", Name: "ContainsKey", Status: MemberBound},
		{Type: "Body", Name: "AsString", Status: MemberExtension},
		{Type: "User", Name: "Name", Status: MemberExtension},
		{Type: "value", Name: "ToString", Status: MemberBound},
		{Type: "string", Name: "Length", Status: MemberBound},
	}
}
