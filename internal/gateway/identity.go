package gateway

import (
	"strings"
	"time"

	"github.com/calvinchengx/azure-apim-emulator/internal/expression"
	"github.com/calvinchengx/azure-apim-emulator/internal/model"
	"github.com/calvinchengx/azure-apim-emulator/internal/store"
)

// The identity graph a policy can read: who is calling, which groups they are
// in, and what the product they came through grants.
//
// Loaded into the snapshot at activation rather than queried per request. A
// policy expression must not put the store on the hot path, and a policy that
// reads `context.User.Groups` in an inbound section would do exactly that.

// loadIdentityGraph fills each service's users, and the groups and APIs its
// products grant.
func loadIdentityGraph(st *store.Store, services []model.Service, apis []model.API, links map[string][]string, snapshot *Snapshot) error {
	// Indexed from the APIs activation already loaded, rather than queried
	// again per product link. A foreign key guarantees a link's API exists, so
	// a second lookup could only fail for reasons that would already have
	// failed activation.
	byID := map[string]model.API{}
	for _, api := range apis {
		byID[strings.ToLower(api.ID())] = api
	}
	for _, item := range services {
		service := snapshot.Services[strings.ToLower(item.Name)]
		if service == nil {
			continue
		}
		users, err := st.ListUsers(item.ID())
		if err != nil {
			return err
		}
		for _, user := range users {
			groups, err := st.ListUserGroups(user.ID())
			if err != nil {
				return err
			}
			service.Users[strings.ToLower(user.ID())] = userContext(user, groups)
		}
		for productID := range service.Products {
			product := service.Products[productID]
			groups, err := st.ListProductGroups(product.ID())
			if err != nil {
				return err
			}
			service.ProductGroups[strings.ToLower(product.ID())] = groupContexts(groups)
			service.ProductApis[strings.ToLower(product.ID())] = apiContexts(byID, links[product.ID()])
		}
	}
	return nil
}

func userContext(user model.User, groups []model.Group) expression.UserContext {
	identities := make([]expression.UserIdentityContext, 0, len(user.Identities))
	for _, identity := range user.Identities {
		identities = append(identities, expression.UserIdentityContext{Id: identity.ID, Provider: identity.Provider})
	}
	registered := ""
	if user.RegistrationAt != 0 {
		registered = time.Unix(user.RegistrationAt, 0).UTC().Format(time.RFC3339)
	}
	return expression.UserContext{
		Id:    user.Name,
		Email: user.Email, FirstName: user.FirstName, LastName: user.LastName,
		Note: user.Note, RegistrationDate: registered,
		Groups: groupContexts(groups), Identities: identities,
	}
}

func groupContexts(groups []model.Group) []expression.GroupContext {
	values := make([]expression.GroupContext, 0, len(groups))
	for _, group := range groups {
		values = append(values, expression.GroupContext{Id: group.Name, Name: displayName(group.DisplayName, group.Name)})
	}
	return values
}

// apiContexts turns a product's API links into the contexts a policy reads.
func apiContexts(byID map[string]model.API, ids []string) []expression.ApiContext {
	values := make([]expression.ApiContext, 0, len(ids))
	for _, id := range ids {
		api := byID[strings.ToLower(id)]
		values = append(values, expression.ApiContext{
			Id: api.Name, Name: displayName(api.DisplayName, api.Name), Path: strings.Trim(api.Path, "/"),
			Revision: api.Revision, Version: api.Version, IsCurrentRevision: api.IsCurrent, ServiceUrl: api.ServiceURL,
		})
	}
	return values
}

// subscriptionOwner resolves the user a subscription belongs to.
//
// The owner is an ARM id in the subscription's stored document; only its last
// segment names the user. A subscription with no owner -- which Azure allows --
// leaves `context.User` null rather than inventing an anonymous one, because a
// policy testing `context.User != null` is asking exactly that question.
func subscriptionOwner(service *Service, subscription model.Subscription) *expression.UserContext {
	properties, _ := subscription.Document["properties"].(map[string]any)
	ownerID, _ := properties["ownerId"].(string)
	if strings.TrimSpace(ownerID) == "" {
		return nil
	}
	name := ownerID
	if index := strings.LastIndex(ownerID, "/"); index >= 0 {
		name = ownerID[index+1:]
	}
	user, ok := service.Users[strings.ToLower(subscription.ServiceID+"/users/"+name)]
	if !ok {
		return nil
	}
	return &user
}
