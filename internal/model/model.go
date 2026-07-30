// Package model contains the version-neutral APIM resource model.
package model

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
	ETag                 string
}

// ID returns the API ARM resource ID.
func (a API) ID() string { return a.ServiceID + "/apis/" + a.Name }

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
