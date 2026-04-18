package azure

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/vatsayanvivek/argus/internal/models"
)

// securityRelevantPrefixes is the list of operation name prefixes we care
// about for drift + audit analysis. These are the writes that either grant
// access, change policy, or touch data-plane surfaces that matter.
var securityRelevantPrefixes = []string{
	"Microsoft.Authorization/roleAssignments/write",
	"Microsoft.Authorization/policyAssignments/write",
	"Microsoft.Network/networkSecurityGroups/write",
	"Microsoft.KeyVault/vaults/delete",
	"Microsoft.Storage/storageAccounts/write",
	"Microsoft.Security/",
}

// DefaultActivityLogDays is the default window for Activity Log collection.
// Azure Monitor retains Activity Log for 90 days out-of-the-box; 30 days is
// long enough to catch recent drift without overloading large subscriptions.
// Users can override via Collector.WithActivityLogDays() or the CLI
// `--activity-log-days` flag.
const DefaultActivityLogDays = 30

// collectActivityLog pulls Activity Log events for the last `days` days and
// keeps only entries that touch security-relevant operations. When days is
// 0 or negative, DefaultActivityLogDays is used. The Azure backend caps at
// 90 days regardless of what we ask for, so callers get whatever the
// backend provides within the requested window.
func collectActivityLog(
	ctx context.Context,
	cred azcore.TokenCredential,
	subscriptionID string,
	days int,
) ([]models.ActivityEvent, error) {
	events := []models.ActivityEvent{}

	if days <= 0 {
		days = DefaultActivityLogDays
	}
	if days > 90 {
		days = 90 // Azure backend cap — asking for more is silently truncated
	}

	client, err := armmonitor.NewActivityLogsClient(subscriptionID, cred, nil)
	if err != nil {
		return events, fmt.Errorf("activity log client: %w", err)
	}

	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	filter := fmt.Sprintf("eventTimestamp ge '%s'", since)

	pager := client.NewListPager(filter, nil)

	pageCount := 0
	const maxPages = 20 // hard cap to keep scans bounded
	for pager.More() && pageCount < maxPages {
		pageCount++
		page, perr := pager.NextPage(ctx)
		if perr != nil {
			soft, code := classifyAzureError(perr)
			if soft {
				log.Printf("[argus/azure] activity log soft-failed (%d): %v", code, perr)
				return events, nil
			}
			return events, fmt.Errorf("activity log page: %w", perr)
		}
		for _, ev := range page.Value {
			if ev == nil {
				continue
			}
			opName := ""
			if ev.OperationName != nil && ev.OperationName.Value != nil {
				opName = *ev.OperationName.Value
			}
			if !isSecurityRelevant(opName) {
				continue
			}
			e := models.ActivityEvent{
				OperationName: opName,
			}
			if ev.Caller != nil {
				e.Caller = *ev.Caller
			}
			if ev.ResourceID != nil {
				e.ResourceID = *ev.ResourceID
				e.ResourceType = extractResourceType(*ev.ResourceID)
			}
			if ev.Status != nil && ev.Status.Value != nil {
				e.Status = *ev.Status.Value
			}
			if ev.EventTimestamp != nil {
				e.Timestamp = *ev.EventTimestamp
			}
			if ev.Category != nil && ev.Category.Value != nil {
				e.Category = *ev.Category.Value
			}
			events = append(events, e)
		}
	}

	return events, nil
}

// isSecurityRelevant returns true when the operation name starts with any of
// the security-interesting prefixes. Case-insensitive — Azure normalizes the
// casing of operation names but we don't rely on that.
func isSecurityRelevant(opName string) bool {
	if opName == "" {
		return false
	}
	lower := strings.ToLower(opName)
	for _, p := range securityRelevantPrefixes {
		if strings.HasPrefix(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// extractResourceType pulls the Azure resource provider + type from a full
// resource ID. e.g.
// /subscriptions/.../resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/foo
// returns "Microsoft.Storage/storageAccounts".
func extractResourceType(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i := 0; i < len(parts)-2; i++ {
		if strings.EqualFold(parts[i], "providers") {
			provider := parts[i+1]
			rtype := parts[i+2]
			return provider + "/" + rtype
		}
	}
	return ""
}
