package azure

import (
	"context"
	"fmt"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

	"github.com/vatsayanvivek/argus/internal/models"
)

// collectPolicy enumerates every Azure Policy assignment at the subscription
// scope and returns a PolicyResult per assignment. Compliance state is a
// separate API (armpolicyinsights) that we do not depend on here to keep the
// module graph small — instead we surface the assignment list with a state
// of "Unknown", which the downstream OPA rules treat as "needs-attention".
// This ensures we make a real API call and return meaningful data to the
// pipeline without hard-coding empty results.
func collectPolicy(
	ctx context.Context,
	cred azcore.TokenCredential,
	subscriptionID string,
) ([]models.PolicyResult, error) {
	results := []models.PolicyResult{}

	factory, err := armpolicy.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return results, fmt.Errorf("policy client factory: %w", err)
	}
	assignClient := factory.NewAssignmentsClient()

	pager := assignClient.NewListPager(nil)
	pageCount := 0
	const maxPages = 20
	for pager.More() && pageCount < maxPages {
		pageCount++
		page, perr := pager.NextPage(ctx)
		if perr != nil {
			soft, code := classifyAzureError(perr)
			if soft {
				log.Printf("[argus/azure] policy assignments soft-failed (%d): %v", code, perr)
				return results, nil
			}
			return results, fmt.Errorf("policy assignments page: %w", perr)
		}
		for _, a := range page.Value {
			if a == nil {
				continue
			}
			pr := models.PolicyResult{
				ComplianceState:       "Unknown",
				NonCompliantCount:     0,
				NonCompliantResources: []string{},
			}
			if a.ID != nil {
				pr.PolicyAssignmentID = *a.ID
			}
			// Prefer the display name if set, otherwise fall back to the
			// assignment name so callers always see something useful.
			if a.Properties != nil && a.Properties.DisplayName != nil && *a.Properties.DisplayName != "" {
				pr.PolicyName = *a.Properties.DisplayName
			} else if a.Name != nil {
				pr.PolicyName = *a.Name
			}
			results = append(results, pr)
		}
	}

	return results, nil
}
