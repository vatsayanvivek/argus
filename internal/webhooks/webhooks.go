// Package webhooks delivers scan-result notifications to external services
// via configurable HTTP webhooks. Supported payload formats: raw JSON,
// Slack Block Kit, and Microsoft Teams Adaptive Cards.
package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// WebhookConfig describes a single webhook destination.
type WebhookConfig struct {
	Name    string            `yaml:"name"    json:"name"`
	URL     string            `yaml:"url"     json:"url"`
	Format  string            `yaml:"format"  json:"format"`  // "json", "slack", "teams"
	Events  []string          `yaml:"events"  json:"events"`  // "on-complete", "on-critical", "on-chain"
	Timeout int               `yaml:"timeout" json:"timeout"` // seconds; 0 means default (10s)
	Headers map[string]string `yaml:"headers" json:"headers"`
}

// ---------------------------------------------------------------------------
// Scan summary (webhook-specific DTO)
// ---------------------------------------------------------------------------

// ChainSummary is a lightweight representation of an attack chain for
// notification payloads — just enough context to be actionable.
type ChainSummary struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Steps    int    `json:"steps"`
}

// ScanSummary is the data envelope passed to every webhook payload builder.
type ScanSummary struct {
	SubscriptionID   string         `json:"subscription_id"`
	SubscriptionName string         `json:"subscription_name"`
	TenantID         string         `json:"tenant_id"`
	ScanTime         string         `json:"scan_time"`
	OverallScore     float64        `json:"overall_score"`
	Grade            string         `json:"grade"`
	TotalFindings    int            `json:"total_findings"`
	CriticalFindings int            `json:"critical_findings"`
	HighFindings     int            `json:"high_findings"`
	TotalChains      int            `json:"total_chains"`
	CriticalChains   int            `json:"critical_chains"`
	TopChains        []ChainSummary `json:"top_chains"`
}

// ---------------------------------------------------------------------------
// Notifier
// ---------------------------------------------------------------------------

// Notifier delivers webhook notifications for completed scans.
type Notifier struct {
	// HTTPClient allows callers (and tests) to inject a custom client.
	// When nil, a default client is created per-request using the config
	// timeout.
	HTTPClient *http.Client
}

// NewNotifier returns a Notifier with default settings.
func NewNotifier() *Notifier {
	return &Notifier{}
}

// Send delivers the scan summary to every webhook whose event filter matches.
// It returns a slice of errors — one per failed delivery. A nil return (or
// zero-length slice) means every delivery succeeded.
func (n *Notifier) Send(summary ScanSummary, configs []WebhookConfig) []error {
	var errs []error
	for _, cfg := range configs {
		if !shouldFire(summary, cfg.Events) {
			continue
		}

		payload, err := buildPayload(summary, cfg.Format)
		if err != nil {
			errs = append(errs, fmt.Errorf("webhook %q: payload build: %w", cfg.Name, err))
			continue
		}

		if err := n.deliver(payload, cfg); err != nil {
			errs = append(errs, fmt.Errorf("webhook %q: %w", cfg.Name, err))
		}
	}
	return errs
}

// ---------------------------------------------------------------------------
// Event filtering
// ---------------------------------------------------------------------------

// shouldFire returns true when at least one event in the config's event list
// matches the current scan summary state.
func shouldFire(summary ScanSummary, events []string) bool {
	if len(events) == 0 {
		// No events configured — treat as "on-complete" (always fire).
		return true
	}
	for _, ev := range events {
		switch ev {
		case "on-complete":
			return true
		case "on-critical":
			if summary.CriticalFindings > 0 {
				return true
			}
		case "on-chain":
			if summary.TotalChains > 0 {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

func buildPayload(summary ScanSummary, format string) ([]byte, error) {
	switch format {
	case "slack":
		return buildSlackPayload(summary)
	case "teams":
		return buildTeamsPayload(summary)
	default: // "json" or anything unrecognised
		return buildJSONPayload(summary)
	}
}

// buildJSONPayload returns the summary as a plain JSON object wrapped in an
// "argus_scan" envelope.
func buildJSONPayload(summary ScanSummary) ([]byte, error) {
	envelope := map[string]interface{}{
		"event":   "argus_scan",
		"version": "1.2",
		"data":    summary,
	}
	return json.Marshal(envelope)
}

// buildSlackPayload produces a Slack Block Kit message.
// Reference: https://api.slack.com/reference/block-kit
func buildSlackPayload(summary ScanSummary) ([]byte, error) {
	scoreEmoji := gradeEmoji(summary.Grade)

	headerText := fmt.Sprintf("%s ARGUS Scan Complete — %s", scoreEmoji, summary.SubscriptionName)

	blocks := []interface{}{
		slackSection(fmt.Sprintf("*%s*", headerText)),
		slackDivider(),
		slackSection(fmt.Sprintf(
			"*Score:* %.1f/100 (%s)\n*Subscription:* `%s`\n*Tenant:* `%s`\n*Scanned:* %s",
			summary.OverallScore, summary.Grade,
			summary.SubscriptionID,
			summary.TenantID,
			summary.ScanTime,
		)),
		slackSection(fmt.Sprintf(
			"*Findings:* %d total | %d critical | %d high\n*Attack Chains:* %d total | %d critical",
			summary.TotalFindings, summary.CriticalFindings, summary.HighFindings,
			summary.TotalChains, summary.CriticalChains,
		)),
	}

	if len(summary.TopChains) > 0 {
		blocks = append(blocks, slackDivider())
		chainsText := "*Top Attack Chains:*\n"
		for _, c := range summary.TopChains {
			chainsText += fmt.Sprintf("  %s `%s` — %s (%d steps)\n",
				severityIcon(c.Severity), c.ID, c.Title, c.Steps)
		}
		blocks = append(blocks, slackSection(chainsText))
	}

	msg := map[string]interface{}{
		"blocks": blocks,
	}
	return json.Marshal(msg)
}

func slackSection(text string) map[string]interface{} {
	return map[string]interface{}{
		"type": "section",
		"text": map[string]interface{}{
			"type": "mrkdwn",
			"text": text,
		},
	}
}

func slackDivider() map[string]interface{} {
	return map[string]interface{}{"type": "divider"}
}

// buildTeamsPayload produces a Microsoft Teams Adaptive Card (webhook
// connector format).
// Reference: https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using
func buildTeamsPayload(summary ScanSummary) ([]byte, error) {
	facts := []map[string]string{
		{"title": "Score", "value": fmt.Sprintf("%.1f/100 (%s)", summary.OverallScore, summary.Grade)},
		{"title": "Subscription", "value": summary.SubscriptionID},
		{"title": "Tenant", "value": summary.TenantID},
		{"title": "Scan Time", "value": summary.ScanTime},
		{"title": "Total Findings", "value": fmt.Sprintf("%d", summary.TotalFindings)},
		{"title": "Critical Findings", "value": fmt.Sprintf("%d", summary.CriticalFindings)},
		{"title": "High Findings", "value": fmt.Sprintf("%d", summary.HighFindings)},
		{"title": "Attack Chains", "value": fmt.Sprintf("%d total / %d critical", summary.TotalChains, summary.CriticalChains)},
	}

	sections := []map[string]interface{}{
		{
			"activityTitle": fmt.Sprintf("%s ARGUS Scan — %s", gradeEmoji(summary.Grade), summary.SubscriptionName),
			"facts":         facts,
			"markdown":      true,
		},
	}

	if len(summary.TopChains) > 0 {
		chainsText := ""
		for _, c := range summary.TopChains {
			chainsText += fmt.Sprintf("- **[%s]** `%s` — %s (%d steps)\n",
				c.Severity, c.ID, c.Title, c.Steps)
		}
		sections = append(sections, map[string]interface{}{
			"activityTitle": "Top Attack Chains",
			"text":          chainsText,
			"markdown":      true,
		})
	}

	card := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor":  themeColor(summary.Grade),
		"summary":    fmt.Sprintf("ARGUS Scan: %s (%.1f)", summary.Grade, summary.OverallScore),
		"sections":   sections,
	}
	return json.Marshal(card)
}

// ---------------------------------------------------------------------------
// HTTP delivery
// ---------------------------------------------------------------------------

func (n *Notifier) deliver(payload []byte, cfg WebhookConfig) error {
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	client := n.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	req, err := http.NewRequest(http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARGUS/1.2")

	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, cfg.URL)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func gradeEmoji(grade string) string {
	switch grade {
	case "A+", "A":
		return "\u2705" // green check
	case "B":
		return "\U0001f7e1" // yellow circle
	case "C":
		return "\U0001f7e0" // orange circle
	default:
		return "\U0001f534" // red circle
	}
}

func severityIcon(sev string) string {
	switch sev {
	case "CRITICAL":
		return "\U0001f534"
	case "HIGH":
		return "\U0001f7e0"
	case "MEDIUM":
		return "\U0001f7e1"
	default:
		return "\u26aa"
	}
}

func themeColor(grade string) string {
	switch grade {
	case "A+", "A":
		return "00cc00"
	case "B":
		return "ffcc00"
	case "C":
		return "ff8800"
	default:
		return "cc0000"
	}
}
