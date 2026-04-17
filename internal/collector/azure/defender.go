package azure

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/vatsayanvivek/argus/internal/models"
)

// collectDefender gathers Microsoft Defender for Cloud state:
//   - Unhealthy assessments (recommendations) scoped to the subscription.
//   - Defender plan tier per service ("Free" vs "Standard").
//   - Overall secure score (ascScore).
//
// Every client call is wrapped; a 403 (e.g., the scanning principal lacks
// Security Reader) degrades the result gracefully instead of bubbling up. The
// function returns a non-nil findings slice + plans map even on total
// failure so downstream code never nil-derefs.
func collectDefender(
	ctx context.Context,
	cred azcore.TokenCredential,
	subscriptionID string,
) ([]models.DefenderFinding, map[string]string, float64, error) {
	findings := []models.DefenderFinding{}
	plans := map[string]string{}
	secureScore := 0.0

	scope := fmt.Sprintf("/subscriptions/%s", subscriptionID)

	// We use the top-level armsecurity.ClientFactory as the one-stop
	// constructor for every sub-client. v0.13.0 exposes NewClientFactory
	// which yields Assessments, Pricings, and SecureScores clients without
	// repeating the credential/options arguments at every site.
	factory, err := armsecurity.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		// A client factory init failure means we cannot reach the Defender
		// plane at all. Surface it as a soft error (log + return zero data)
		// so the parent collector records it and keeps going.
		log.Printf("[argus/azure] defender client factory init: %v", err)
		return findings, plans, secureScore, nil
	}

	// ---- Assessments (recommendations) ----
	assessClient := factory.NewAssessmentsClient()
	assessPager := assessClient.NewListPager(scope, nil)
	for assessPager.More() {
		page, perr := assessPager.NextPage(ctx)
		if perr != nil {
			soft, code := classifyAzureError(perr)
			if soft {
				log.Printf("[argus/azure] defender assessments soft-failed (%d): %v", code, perr)
				break
			}
			return findings, plans, secureScore, fmt.Errorf("defender assessments: %w", perr)
		}
		for _, a := range page.Value {
			if a == nil || a.Properties == nil {
				continue
			}
			// Filter to Unhealthy only — healthy assessments are not
			// findings, they're confirmations the baseline passed.
			statusCode := ""
			if a.Properties.Status != nil && a.Properties.Status.Code != nil {
				statusCode = string(*a.Properties.Status.Code)
			}
			if !strings.EqualFold(statusCode, "Unhealthy") {
				continue
			}
			f := models.DefenderFinding{Status: statusCode}
			if a.ID != nil {
				f.ID = *a.ID
			}
			if a.Name != nil {
				f.Name = *a.Name
			}
			if a.Properties.DisplayName != nil {
				f.DisplayName = *a.Properties.DisplayName
			}
			// ResourceDetails is a discriminated union (AzureResourceDetails
			// for Azure-native resources, OnPremiseResourceDetails for Arc,
			// etc.). We only surface the Azure variant — anything else keeps
			// f.ResourceID empty.
			if a.Properties.ResourceDetails != nil {
				if azRD, ok := a.Properties.ResourceDetails.(*armsecurity.AzureResourceDetails); ok {
					if azRD.ID != nil {
						f.ResourceID = *azRD.ID
					}
				}
			}
			if a.Properties.Metadata != nil {
				if a.Properties.Metadata.Severity != nil {
					f.Severity = string(*a.Properties.Metadata.Severity)
				}
				if a.Properties.Metadata.Description != nil {
					f.Description = *a.Properties.Metadata.Description
				}
				if a.Properties.Metadata.RemediationDescription != nil {
					f.RemediationURL = *a.Properties.Metadata.RemediationDescription
				}
			}
			findings = append(findings, f)
		}
	}

	// ---- Defender plans (pricing tiers) ----
	priceClient := factory.NewPricingsClient()
	if priceResp, perr := priceClient.List(ctx, scope, nil); perr != nil {
		soft, code := classifyAzureError(perr)
		if soft {
			log.Printf("[argus/azure] defender pricings soft-failed (%d): %v", code, perr)
		} else {
			return findings, plans, secureScore, fmt.Errorf("defender pricings: %w", perr)
		}
	} else if priceResp.Value != nil {
		for _, p := range priceResp.Value {
			if p == nil || p.Name == nil || p.Properties == nil {
				continue
			}
			tier := "Free"
			if p.Properties.PricingTier != nil {
				tier = string(*p.Properties.PricingTier)
			}
			plans[*p.Name] = tier
		}
	}

	// ---- Secure score (ascScore) ----
	// The "ascScore" endpoint frequently returns 404 in subscriptions where
	// Defender for Cloud has never been initialised. That is not an error
	// from ARGUS's perspective — we leave secureScore at 0 and silently
	// continue. Only non-soft errors are logged loudly.
	scoreClient := factory.NewSecureScoresClient()
	if scoreResp, serr := scoreClient.Get(ctx, "ascScore", nil); serr != nil {
		soft, _ := classifyAzureError(serr)
		if !soft {
			return findings, plans, secureScore, fmt.Errorf("defender secure score: %w", serr)
		}
		// soft failure: silently leave secureScore = 0
	} else if scoreResp.Properties != nil && scoreResp.Properties.Score != nil && scoreResp.Properties.Score.Percentage != nil {
		secureScore = *scoreResp.Properties.Score.Percentage
	}

	return findings, plans, secureScore, nil
}
