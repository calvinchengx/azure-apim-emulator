// Package model contains the version-neutral APIM resource model.
package model

import "time"

// Service identifies one logical APIM instance.
type Service struct {
	SubscriptionID    string
	ResourceGroup     string
	Name              string
	Location          string
	SKUName           string
	SKUCapacity       int
	PublisherName     string
	PublisherEmail    string
	ProvisioningState string
	ETag              string
	Document          map[string]any
}

// ID returns the ARM resource ID.
func (s Service) ID() string {
	return "/subscriptions/" + s.SubscriptionID + "/resourceGroups/" + s.ResourceGroup +
		"/providers/Microsoft.ApiManagement/service/" + s.Name
}

// API is an API configured on a service.
type API struct {
	ServiceID            string
	Name                 string
	DisplayName          string
	Path                 string
	ServiceURL           string
	Protocols            []string
	SubscriptionRequired bool
	Revision             string
	RevisionDescription  string
	IsCurrent            bool
	CreatedAt            int64
	UpdatedAt            int64
	Version              string
	VersionSetID         string
	ETag                 string
	Document             map[string]any
}

// APIDefinition retains the source document used to import an API.
type APIDefinition struct {
	APIID     string
	Format    string
	Value     string
	SourceURL string
	ETag      string
}

// ID returns the API ARM resource ID.
func (a API) ID() string { return a.ServiceID + "/apis/" + a.Name }

// APIRelease records promotion of an API revision.
type APIRelease struct {
	APIID       string
	Name        string
	TargetAPIID string
	Notes       string
	CreatedAt   int64
	UpdatedAt   int64
	ETag        string
	Document    map[string]any
}

// ID returns the release ARM resource ID.
func (r APIRelease) ID() string { return r.APIID + "/releases/" + r.Name }

// APIVersionSet defines how clients select an API version.
type APIVersionSet struct {
	ServiceID         string
	Name              string
	DisplayName       string
	VersioningScheme  string
	VersionHeaderName string
	VersionQueryName  string
	Description       string
	ETag              string
	Document          map[string]any
}

// ID returns the API version-set ARM resource ID.
func (v APIVersionSet) ID() string { return v.ServiceID + "/apiVersionSets/" + v.Name }

// NamedValue is a reusable value referenced from APIM policy XML.
type NamedValue struct {
	ServiceID             string
	Name                  string
	DisplayName           string
	Value                 string
	Tags                  []string
	Secret                bool
	KeyVaultSecretID      string
	KeyVaultIdentityID    string
	KeyVaultStatusCode    string
	KeyVaultStatusMessage string
	KeyVaultStatusTime    time.Time
	ETag                  string
	Document              map[string]any
}

// ID returns the named value ARM resource ID.
func (v NamedValue) ID() string { return v.ServiceID + "/namedValues/" + v.Name }

// Backend is a reusable gateway destination and its lossless ARM document.
type Backend struct {
	ServiceID   string
	Name        string
	Title       string
	Description string
	URL         string
	Protocol    string
	ResourceID  string
	ETag        string
	Document    map[string]any
}

// ID returns the backend ARM resource ID.
func (v Backend) ID() string { return v.ServiceID + "/backends/" + v.Name }

// Cache is an external Redis-compatible cache associated with a service.
type Cache struct {
	ServiceID        string
	Name             string
	Description      string
	ConnectionString string
	UseFromLocation  string
	ResourceID       string
	ETag             string
	Document         map[string]any
}

// ID returns the cache ARM resource ID.
func (v Cache) ID() string { return v.ServiceID + "/caches/" + v.Name }

// IdentityProvider is a developer-portal identity provider configuration.
type IdentityProvider struct {
	ServiceID                string
	Name                     string
	ClientID                 string
	ClientSecret             string
	Authority                string
	SigninTenant             string
	SignupPolicyName         string
	SigninPolicyName         string
	ProfileEditingPolicyName string
	PasswordResetPolicyName  string
	AllowedTenants           []string
	ETag                     string
	Document                 map[string]any
}

// ID returns the identity provider ARM resource ID.
func (v IdentityProvider) ID() string { return v.ServiceID + "/identityProviders/" + v.Name }

// OpenIDConnectProvider is an OpenID Connect provider configuration.
type OpenIDConnectProvider struct {
	ServiceID        string
	Name             string
	DisplayName      string
	Description      string
	MetadataEndpoint string
	ClientID         string
	ClientSecret     string
	ETag             string
	Document         map[string]any
}

// ID returns the OpenID Connect provider ARM resource ID.
func (v OpenIDConnectProvider) ID() string { return v.ServiceID + "/openidConnectProviders/" + v.Name }

// AuthorizationServer is an external OAuth authorization server configuration.
type AuthorizationServer struct {
	ServiceID                  string
	Name                       string
	DisplayName                string
	Description                string
	AuthorizationEndpoint      string
	ClientRegistrationEndpoint string
	ClientID                   string
	ClientSecret               string
	TokenEndpoint              string
	DefaultScope               string
	ResourceOwnerUsername      string
	ResourceOwnerPassword      string
	SupportState               bool
	GrantTypes                 []string
	ETag                       string
	Document                   map[string]any
}

// ID returns the authorization server ARM resource ID.
func (v AuthorizationServer) ID() string { return v.ServiceID + "/authorizationServers/" + v.Name }

// Documentation is a service-scoped markdown documentation article.
type Documentation struct {
	ServiceID string
	Name      string
	Title     string
	Content   string
	ETag      string
	Document  map[string]any
}

// ID returns the documentation ARM resource ID.
func (v Documentation) ID() string { return v.ServiceID + "/documentations/" + v.Name }

// GlobalSchema is a schema shared across a service's APIs, at `/schemas/{id}`.
//
// NOT the same family as APISchema, which hangs off one API at
// `/apis/{id}/schemas/{id}`. Azure spells both segments `schemas`, which is why
// the two are distinguished by depth rather than by name.
//
// The field split follows Microsoft's own contract rather than convenience:
// `value` carries a json-ENCODED STRING for a non-json schema (an XSD), while
// `document` carries an object for a json schema. A single field would have to
// guess which one a caller meant.
type GlobalSchema struct {
	ServiceID   string
	Name        string
	SchemaType  string // "xml" or "json"; the contract marks it Immutable
	Description string
	Value       string
	Schema      map[string]any // properties.document
	Document    map[string]any // the lossless ARM document
	ETag        string
}

// ID returns the global schema ARM resource ID.
func (v GlobalSchema) ID() string { return v.ServiceID + "/schemas/" + v.Name }

// TenantAccess is a service's direct-management access configuration, at
// `/tenant/{accessName}`.
//
// It is a SINGLETON PAIR, not a collection: Microsoft's `AccessIdName` enum has
// exactly two members, `access` (the Management REST API) and `gitAccess` (the
// configuration git repository), and both exist for every service from the
// moment it does. There is no create and no delete in the contract; the PUT is
// spelled `Create` but its only declared response is 200, never 201.
//
// The keys are held here but must never leave through a GET. Microsoft splits
// the surface into two models for exactly that reason:
// `AccessInformationContract` (the GET/PUT/PATCH body) has no key fields at
// all, while `AccessInformationSecretsContract` (the `/listSecrets` body) does
// and is not even wrapped in `properties`.
type TenantAccess struct {
	ServiceID string
	// Name is `access` or `gitAccess`, and doubles as `properties.id`.
	Name         string
	PrincipalID  string
	PrimaryKey   string
	SecondaryKey string
	Enabled      bool
	ETag         string
}

// ID returns the tenant access ARM resource ID.
func (v TenantAccess) ID() string { return v.ServiceID + "/tenant/" + v.Name }

// Certificate is backend client-certificate material or a Key Vault reference.
type Certificate struct {
	ServiceID             string
	Name                  string
	Subject               string
	Thumbprint            string
	Expiration            time.Time
	Data                  []byte
	Password              string
	KeyVaultSecretID      string
	KeyVaultIdentityID    string
	KeyVaultStatusCode    string
	KeyVaultStatusMessage string
	KeyVaultStatusTime    time.Time
	ETag                  string
	Document              map[string]any
}

// ID returns the certificate ARM resource ID.
func (v Certificate) ID() string { return v.ServiceID + "/certificates/" + v.Name }

// APISchema is a lossless schema document owned by one API revision.
type APISchema struct {
	APIID       string
	Name        string
	ContentType string
	Document    map[string]any
	ARMDocument map[string]any
	ETag        string
}

// ID returns the API schema ARM resource ID.
func (v APISchema) ID() string { return v.APIID + "/schemas/" + v.Name }

// Workspace is a team-scoped container inside a service. Every APIM resource
// family can be parented to a workspace instead of to the service, which is why
// it is modelled as a scope rather than as another resource kind.
type Workspace struct {
	ServiceID   string
	Name        string
	DisplayName string
	Description string
	Document    map[string]any
	ETag        string
}

// ID returns the workspace ARM resource ID.
func (v Workspace) ID() string { return v.ServiceID + "/workspaces/" + v.Name }

// APIResolver binds one GraphQL schema field to a data source. Azure addresses
// it by Type and Field (the portal calls the pair a "path", e.g. Query/items),
// and the resolver's own policy at .../resolvers/{name}/policies/policy holds
// the <http-data-source> that produces the value.
type APIResolver struct {
	APIID       string
	Name        string
	DisplayName string
	Description string
	Type        string
	Field       string
	Document    map[string]any
	ETag        string
}

// ID returns the API resolver ARM resource ID.
func (v APIResolver) ID() string { return v.APIID + "/resolvers/" + v.Name }

// Tag is reusable metadata associated with APIs, operations, and products.
type Tag struct {
	ServiceID   string
	Name        string
	DisplayName string
	ETag        string
	Document    map[string]any
}

// ID returns the tag ARM resource ID.
func (v Tag) ID() string { return v.ServiceID + "/tags/" + v.Name }

// Group controls developer visibility and membership.
type Group struct {
	ServiceID   string
	Name        string
	DisplayName string
	Description string
	Type        string
	ExternalID  string
	BuiltIn     bool
	ETag        string
	Document    map[string]any
}

// ID returns the group ARM resource ID.
func (v Group) ID() string { return v.ServiceID + "/groups/" + v.Name }

// UserIdentity links a user to an identity provider account.
type UserIdentity struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
}

// User is a developer account registered with an APIM service.
type User struct {
	ServiceID      string
	Name           string
	FirstName      string
	LastName       string
	Email          string
	State          string
	Note           string
	Identities     []UserIdentity
	RegistrationAt int64
	Password       string
	PrimaryKey     string
	SecondaryKey   string
	ETag           string
	Document       map[string]any
}

// ID returns the user ARM resource ID.
func (v User) ID() string { return v.ServiceID + "/users/" + v.Name }

// PolicyFragment is reusable policy XML included by other policies.
type PolicyFragment struct {
	ServiceID         string
	Name              string
	Description       string
	Format            string
	Value             string
	ProvisioningState string
	ETag              string
	Document          map[string]any
}

// ID returns the policy fragment ARM resource ID.
func (v PolicyFragment) ID() string { return v.ServiceID + "/policyFragments/" + v.Name }

// Logger is a diagnostic event sink configured on a service.
type Logger struct {
	ServiceID   string
	Name        string
	LoggerType  string
	Description string
	IsBuffered  bool
	ResourceID  string
	Credentials map[string]string
	Document    map[string]any
	ETag        string
}

// ID returns the logger ARM resource ID.
func (v Logger) ID() string { return v.ServiceID + "/loggers/" + v.Name }

// Diagnostic configures telemetry at service or API scope.
type Diagnostic struct {
	ServiceID          string
	ScopeID            string
	Name               string
	LoggerID           string
	AlwaysLog          string
	LogClientIP        bool
	Verbosity          string
	SamplingType       string
	SamplingPercentage float64
	Document           map[string]any
	ETag               string
}

// ID returns the diagnostic ARM resource ID.
func (v Diagnostic) ID() string { return v.ScopeID + "/diagnostics/" + v.Name }

// DiagnosticEvent is one locally persisted gateway telemetry event.
type DiagnosticEvent struct {
	ID            string
	ServiceID     string
	APIID         string
	DiagnosticID  string
	CorrelationID string
	Method        string
	Path          string
	StatusCode    int
	Timestamp     int64
	DurationNanos int64
	ClientIP      string
	Metadata      map[string]any
}

// Operation is an HTTP operation belonging to an API.
type Operation struct {
	APIID       string
	Name        string
	DisplayName string
	Method      string
	URLTemplate string
	ETag        string
	Document    map[string]any
}

// Product is an APIM product.
type Product struct {
	ServiceID        string
	Name             string
	DisplayName      string
	State            string
	ApprovalRequired bool
	ETag             string
	Document         map[string]any
}

// ID returns the product ARM resource ID.
func (p Product) ID() string { return p.ServiceID + "/products/" + p.Name }

// Subscription is a gateway subscription.
type Subscription struct {
	ServiceID    string
	Name         string
	DisplayName  string
	Scope        string
	State        string
	PrimaryKey   string
	SecondaryKey string
	ETag         string
	Document     map[string]any
}

// ID returns the subscription ARM resource ID.
func (s Subscription) ID() string { return s.ServiceID + "/subscriptions/" + s.Name }

// Policy stores the original APIM policy document for a scope.
type Policy struct {
	ScopeID string
	Format  string
	Value   string
	ETag    string
}

// AuthorizationProvider is a credential-manager identity provider: the OAuth2
// service APIM will obtain and store tokens from.
//
// Distinct from AuthorizationServer, which is the OAuth2 server the DEVELOPER
// PORTAL sends users to for its own console. The names are one word apart and
// the resources are unrelated.
type AuthorizationProvider struct {
	ServiceID        string
	Name             string
	DisplayName      string
	IdentityProvider string
	Document         map[string]any
	ETag             string
}

// ID returns the authorization provider ARM resource ID.
func (v AuthorizationProvider) ID() string {
	return v.ServiceID + "/authorizationProviders/" + v.Name
}

// Authorization is one stored credential under a provider.
type Authorization struct {
	ProviderID        string
	Name              string
	AuthorizationType string
	OAuth2GrantType   string
	// Status and Error mirror what Azure reports once a credential has been
	// consented. A credential that was never consented is not usable, and the
	// gateway has to be able to tell the two apart.
	Status   string
	ErrorMsg string
	Document map[string]any
	ETag     string
}

// ID returns the authorization ARM resource ID.
func (v Authorization) ID() string { return v.ProviderID + "/authorizations/" + v.Name }

// AuthorizationAccessPolicy names a principal permitted to use a credential.
type AuthorizationAccessPolicy struct {
	AuthorizationID string
	Name            string
	TenantID        string
	ObjectID        string
	Document        map[string]any
	ETag            string
}

// ID returns the access-policy ARM resource ID.
func (v AuthorizationAccessPolicy) ID() string {
	return v.AuthorizationID + "/accessPolicies/" + v.Name
}

// Gateway is a self-hosted gateway registered against a service.
//
// The resource is a REGISTRATION, not a process: Azure hands out a pair of keys
// and a token minted from them, and a gateway container elsewhere presents that
// token to collect its configuration. What the registration decides is which
// APIs that gateway is allowed to serve, which is why the association below is
// the part with runtime consequences.
type Gateway struct {
	ServiceID string
	Name      string
	// LocationName is the only required field of Azure's locationData, and it
	// is free text: a gateway runs wherever its operator ran it, so Azure does
	// not validate it against the Azure region list.
	LocationName string
	Description  string
	// PrimaryKey and SecondaryKey sign the gateway's access token. They are
	// never returned by a GET; listKeys is the only way to read them, exactly
	// as with a subscription's keys.
	PrimaryKey   string
	SecondaryKey string
	Document     map[string]any
	ETag         string
}

// ID returns the gateway ARM resource ID.
func (v Gateway) ID() string { return v.ServiceID + "/gateways/" + v.Name }

// GatewayHostnameConfiguration is one hostname a self-hosted gateway answers on.
//
// This is what makes a self-hosted gateway addressable independently of the
// service's own hostnames, and so it is what the emulator routes on: a request
// arriving on this hostname is served by THIS gateway, and therefore only by
// the APIs associated with it.
type GatewayHostnameConfiguration struct {
	GatewayID string
	Name      string
	Hostname  string
	// CertificateID names a certificate resource on the same service. Azure
	// requires it to exist; a hostname configuration pointing at a certificate
	// nobody uploaded would present no chain at all.
	CertificateID              string
	NegotiateClientCertificate bool
	TLS10Enabled               bool
	TLS11Enabled               bool
	HTTP2Enabled               bool
	Document                   map[string]any
	ETag                       string
}

// ID returns the hostname-configuration ARM resource ID.
func (v GatewayHostnameConfiguration) ID() string {
	return v.GatewayID + "/hostnameConfigurations/" + v.Name
}

// GatewayCertificateAuthority marks one of the service's certificates as
// trusted, or explicitly not trusted, for client-certificate validation on a
// single gateway. Trust is per gateway rather than per service because the
// gateways run in different places and answer to different callers.
type GatewayCertificateAuthority struct {
	GatewayID string
	Name      string
	IsTrusted bool
	Document  map[string]any
	ETag      string
}

// ID returns the certificate-authority ARM resource ID.
func (v GatewayCertificateAuthority) ID() string {
	return v.GatewayID + "/certificateAuthorities/" + v.Name
}

// PrivateEndpointConnection is one private-link connection request against a
// service, and the decision taken on it.
//
// The resource is a HANDSHAKE between two owners: a consumer creates the
// endpoint in their own network and the service owner approves or rejects it.
// That is why the connection state, not the endpoint, is what this resource is
// really about.
type PrivateEndpointConnection struct {
	ServiceID string
	Name      string
	// Status is Pending, Approved or Rejected. A connection only carries
	// traffic once approved, which is the whole point of the workflow.
	Status          string
	Description     string
	ActionsRequired string
	// EndpointID is the consumer's Microsoft.Network/privateEndpoints resource.
	// It lives in a different subscription and this emulator never reaches it.
	EndpointID string
	Document   map[string]any
	ETag       string
}

// ID returns the private-endpoint-connection ARM resource ID.
func (v PrivateEndpointConnection) ID() string {
	return v.ServiceID + "/privateEndpointConnections/" + v.Name
}
