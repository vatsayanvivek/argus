package azure

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	"github.com/vatsayanvivek/argus/internal/models"
)

// collectAzureRBAC enumerates Azure RBAC role assignments visible at the
// subscription scope (including assignments inherited from management
// groups and assignments scoped down to resource groups or individual
// resources) and returns them along with a role-definition-ID → name
// map so each assignment can carry its human role name.
//
// This function soft-fails: if the Authorization API returns an error
// the caller continues with an empty slice so one missing dataset does
// not fail the whole scan. A limited identity without RBAC Reader will
// see the pathfinder produce fewer discovered chains, not an aborted
// scan.
func collectAzureRBAC(ctx context.Context, cred *azidentity.DefaultAzureCredential, subscriptionID string) []models.RoleAssignment {
	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)

	factory, err := armauthorization.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		log.Printf("[argus/azure] rbac client factory: %v", err)
		return nil
	}

	// Resolve role definitions first so we can decorate each assignment
	// with the role name (Contributor, Owner, Reader, etc.). A missing
	// role-defs response is not fatal — assignments without a name will
	// fall back to the role definition ID, which is less readable but
	// still useful for pathfinding.
	roleNames := loadRoleDefinitions(ctx, factory.NewRoleDefinitionsClient(), scope)

	var out []models.RoleAssignment
	assignmentsClient := factory.NewRoleAssignmentsClient()
	pager := assignmentsClient.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Printf("[argus/azure] rbac list assignments soft-failed: %v", err)
			return out
		}
		for _, ra := range page.Value {
			if ra == nil || ra.Properties == nil {
				continue
			}
			roleDefID := strFrom(ra.Properties.RoleDefinitionID)
			principalID := strFrom(ra.Properties.PrincipalID)
			principalType := strFrom((*string)(ra.Properties.PrincipalType))
			raScope := strFrom(ra.Properties.Scope)

			name := ""
			if roleDefID != "" {
				// Role definition IDs can appear as full or short form;
				// normalise to the last path segment for map lookup.
				if n, ok := roleNames[normaliseRoleDefID(roleDefID)]; ok {
					name = n
				}
			}

			out = append(out, models.RoleAssignment{
				ID:               strFrom(ra.ID),
				RoleDefinitionID: roleDefID,
				RoleName:         name,
				PrincipalID:      principalID,
				PrincipalType:    principalType,
				Scope:            raScope,
			})
		}
	}
	return out
}

// loadRoleDefinitions builds a roleDefinitionID → displayName map for
// the given scope. Calls NewRoleDefinitionsClient under the covers.
func loadRoleDefinitions(ctx context.Context, client *armauthorization.RoleDefinitionsClient, scope string) map[string]string {
	names := make(map[string]string, 128)
	pager := client.NewListPager(scope, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			log.Printf("[argus/azure] rbac list role definitions soft-failed: %v", err)
			return names
		}
		for _, rd := range page.Value {
			if rd == nil || rd.Properties == nil {
				continue
			}
			if rd.Name == nil {
				continue
			}
			names[*rd.Name] = strFrom(rd.Properties.RoleName)
		}
	}
	return names
}

// normaliseRoleDefID returns the final path segment of a role
// definition ID — e.g. "b24988ac-6180-42a0-ab88-20f7382dd24c" from
// "/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/b24988ac-...".
// The role definitions API returns entries keyed by this short GUID.
func normaliseRoleDefID(id string) string {
	if idx := strings.LastIndex(id, "/"); idx >= 0 && idx < len(id)-1 {
		return id[idx+1:]
	}
	return id
}

func strFrom(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ensureSDKRefs is a compile-time guard that we actually import the
// SDK client helpers. Removing the Subscription import path should
// fail compile here.
var _ = arm.NewClient
