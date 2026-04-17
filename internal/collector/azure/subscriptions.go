package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Subscription is a single Azure subscription discovered via the
// management.azure.com /subscriptions endpoint or under a management
// group.
type Subscription struct {
	ID       string `json:"subscriptionId"`
	Name     string `json:"displayName"`
	State    string `json:"state"`
	TenantID string `json:"tenantId"`
}

// rawSubscription matches the ARM REST shape used by the
// /subscriptions and /managementGroups endpoints. We accept both the
// flat "subscriptionId" form and the nested resource form (where the
// subscription is the resource itself with id="/subscriptions/<guid>").
type rawSubscription struct {
	ID             string `json:"id"`
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
	TenantID       string `json:"tenantId"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Properties     struct {
		DisplayName    string `json:"displayName"`
		State          string `json:"state"`
		TenantID       string `json:"tenantId"`
		SubscriptionID string `json:"subscriptionId"`
	} `json:"properties"`
}

// armListResponse is the standard ARM page wrapper.
type armListResponse struct {
	Value    []rawSubscription `json:"value"`
	NextLink string            `json:"nextLink"`
}

// ListSubscriptions returns every Enabled subscription the supplied
// credential can see in the tenant. State==Enabled is the only filter
// applied; the caller can further filter to dev/prod/etc by name.
//
// Pages are followed until exhausted. Failures return whatever was
// gathered so far so the scan can still proceed against the partial
// list — never returns nil with no error.
func ListSubscriptions(
	ctx context.Context,
	credential *azidentity.DefaultAzureCredential,
) ([]Subscription, error) {
	out := []Subscription{}
	if credential == nil {
		return out, fmt.Errorf("subscriptions: nil credential")
	}

	endpoint := "https://management.azure.com/subscriptions?api-version=2022-12-01"
	pages, err := pageThroughARM(ctx, credential, endpoint)
	if err != nil {
		return out, err
	}
	for _, raw := range pages {
		s := normaliseSubscription(raw)
		if s.State == "" || s.State == "Enabled" {
			out = append(out, s)
		}
	}
	return out, nil
}

// ListSubscriptionsUnderManagementGroup returns every Enabled
// subscription nested under the given management group ID.
func ListSubscriptionsUnderManagementGroup(
	ctx context.Context,
	credential *azidentity.DefaultAzureCredential,
	managementGroupID string,
) ([]Subscription, error) {
	out := []Subscription{}
	if credential == nil {
		return out, fmt.Errorf("subscriptions: nil credential")
	}
	if managementGroupID == "" {
		return out, fmt.Errorf("subscriptions: management group id is required")
	}

	endpoint := fmt.Sprintf(
		"https://management.azure.com/providers/Microsoft.Management/managementGroups/%s/descendants?api-version=2020-05-01",
		url.PathEscape(managementGroupID),
	)
	pages, err := pageThroughARM(ctx, credential, endpoint)
	if err != nil {
		return out, err
	}
	for _, raw := range pages {
		// The descendants endpoint returns mixed objects (subscriptions
		// AND nested management groups). Keep only subscriptions.
		if raw.Type != "" && raw.Type != "Microsoft.Management/managementGroups/subscriptions" {
			continue
		}
		s := normaliseSubscription(raw)
		if s.ID == "" {
			continue
		}
		if s.State == "" || s.State == "Enabled" {
			out = append(out, s)
		}
	}
	return out, nil
}

// pageThroughARM fetches every page of an ARM list response. nextLink
// returns absolute URLs so we follow them verbatim.
func pageThroughARM(
	ctx context.Context,
	credential *azidentity.DefaultAzureCredential,
	endpoint string,
) ([]rawSubscription, error) {
	var out []rawSubscription

	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return out, fmt.Errorf("subscriptions: token: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	page := endpoint
	const maxPages = 50
	pageCount := 0
	for page != "" && pageCount < maxPages {
		pageCount++
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, page, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			return out, fmt.Errorf("subscriptions: ARM %d: %s", resp.StatusCode, string(body))
		}

		var parsed armListResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return out, fmt.Errorf("subscriptions: parse: %w", err)
		}
		out = append(out, parsed.Value...)
		page = parsed.NextLink
	}
	return out, nil
}

// normaliseSubscription flattens the various ARM shapes into our type.
func normaliseSubscription(raw rawSubscription) Subscription {
	s := Subscription{
		ID:       raw.SubscriptionID,
		Name:     raw.DisplayName,
		State:    raw.State,
		TenantID: raw.TenantID,
	}
	// Fall back to nested .properties when the flat fields are empty
	// (descendants endpoint shape).
	if s.ID == "" {
		s.ID = raw.Properties.SubscriptionID
	}
	if s.ID == "" && raw.Name != "" {
		s.ID = raw.Name
	}
	if s.Name == "" {
		s.Name = raw.Properties.DisplayName
	}
	if s.State == "" {
		s.State = raw.Properties.State
	}
	if s.TenantID == "" {
		s.TenantID = raw.Properties.TenantID
	}
	return s
}
