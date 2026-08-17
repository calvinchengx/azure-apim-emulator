package expression

// The expression surface Azure documents, as opposed to the one this emulator
// implements.
//
// WHY THIS FILE EXISTS, and it is the whole point of the inventory. `Allowlist`
// is maintained from the emulator's side: a member is listed because somebody
// here thought about it. `docs/generated/expression-members.json` is generated
// from that allowlist, and the existing tests bind the two together. All of
// that is self-referential -- it can prove the emulator is consistent with
// itself and can never show a member Azure documents that nobody here has heard
// of. Before this file the inventory reported 57 of 66 members bound, which read
// as 86% of the surface and was really 86% of our own list.
//
// So this is the OTHER side, and the gate in allowlist_test.go requires every
// entry here to appear in the allowlist with some status. A member Azure adds
// that nobody implements is then a `planned` row somebody has to write, rather
// than an absence nothing can detect.
//
// PROVENANCE, stated because it bounds what this proves: transcribed from
// Microsoft's published policy-expressions reference, NOT captured from a
// running APIM instance. It is therefore evidence about the documentation, and
// a member Azure supports but does not document is still invisible here. The
// same caveat the tier catalogue carries, for the same reason.

// Documented returns the type/member pairs Microsoft's policy-expression
// reference lists for the `context` object graph.
//
// Helper members the binder needs but Azure does not document as part of the
// context graph -- string methods, `value` coercions -- are deliberately absent:
// this list is the contract, not the implementation's vocabulary.
func Documented() []Member {
	members := []Member{}
	add := func(typ string, names ...string) {
		for _, name := range names {
			members = append(members, Member{Type: typ, Name: name})
		}
	}
	add("context",
		"Api", "Deployment", "Elapsed", "GraphQL", "LastError", "Operation",
		"Product", "Request", "RequestId", "Response", "Subscription",
		"Timestamp", "Tracing", "User", "Variables")
	add("Api", "Id", "IsCurrentRevision", "Name", "Path", "Revision", "ServiceUrl", "Version")
	add("Deployment", "Certificates", "Gateway", "GatewayId", "Region", "ServiceId", "ServiceName")
	add("Gateway", "Id", "InstanceId", "IsManaged", "RegionName")
	add("LastError", "Element", "ElementPath", "Message", "Reason", "Scope", "Section", "Source")
	add("Operation", "Id", "Method", "Name", "UrlTemplate")
	add("Product", "Apis", "ApprovalRequired", "Groups", "Id", "Name", "State",
		"SubscriptionRequired", "SubscriptionsLimit")
	add("Request", "Body", "Certificate", "Headers", "IpAddress", "MatchedParameters",
		"Method", "OriginalUrl", "Url")
	add("Response", "Body", "Headers", "StatusCode", "StatusReason")
	add("Subscription", "CreatedDate", "EndDate", "Id", "Key", "Name", "PrimaryKey",
		"SecondaryKey", "StartDate")
	add("User", "Email", "FirstName", "Groups", "Id", "Identities", "LastName",
		"Note", "RegistrationDate")
	add("Group", "Id", "Name")
	add("UserIdentity", "Id", "Provider")
	add("Url", "Host", "Path", "Port", "Query", "QueryString", "Scheme")
	// X509Certificate2, which `context.Request.Certificate` and each entry of
	// `context.Deployment.Certificates` bind to. Only the members APIM's own
	// examples use are listed: the .NET type has dozens this gateway would have
	// no way to answer.
	add("Certificate", "Issuer", "NotAfter", "NotBefore", "SerialNumber", "Subject", "Thumbprint", "Verify")
	add("Body", "As", "AsFormUrlEncodedContent")
	add("GraphQL", "Arguments", "Parent")
	return members
}

// documentedIndex is Documented() keyed for lookup.
func documentedIndex() map[string]map[string]bool {
	index := map[string]map[string]bool{}
	for _, member := range Documented() {
		if index[member.Type] == nil {
			index[member.Type] = map[string]bool{}
		}
		index[member.Type][member.Name] = true
	}
	return index
}
