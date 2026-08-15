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
