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
}

// ID returns the API version-set ARM resource ID.
func (v APIVersionSet) ID() string { return v.ServiceID + "/apiVersionSets/" + v.Name }

// NamedValue is a reusable value referenced from APIM policy XML.
type NamedValue struct {
	ServiceID          string
	Name               string
	DisplayName        string
	Value              string
	Tags               []string
	Secret             bool
	KeyVaultSecretID   string
	KeyVaultIdentityID string
	ETag               string
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

// Certificate is backend client-certificate material or a Key Vault reference.
type Certificate struct {
	ServiceID          string
	Name               string
	Subject            string
	Thumbprint         string
	Expiration         time.Time
	Data               []byte
	Password           string
	KeyVaultSecretID   string
	KeyVaultIdentityID string
	ETag               string
}

// ID returns the certificate ARM resource ID.
func (v Certificate) ID() string { return v.ServiceID + "/certificates/" + v.Name }

// Operation is an HTTP operation belonging to an API.
type Operation struct {
	APIID       string
	Name        string
	DisplayName string
	Method      string
	URLTemplate string
	ETag        string
}

// Product is an APIM product.
type Product struct {
	ServiceID        string
	Name             string
	DisplayName      string
	State            string
	ApprovalRequired bool
	ETag             string
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
