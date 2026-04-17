// Package suppression implements .argusignore file parsing and finding
// filtering. Suppressions let security teams accept risk on specific
// findings without losing the audit trail — every suppressed finding is
// still recorded in the report's "Suppressed Findings" section with the
// reason and approver.
package suppression

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vatsayanvivek/argus/internal/models"
)

// Suppression is a single rule + (optional) resource scope that
// instructs ARGUS to move matching findings into the suppressed list.
type Suppression struct {
	RuleID     string `yaml:"rule_id"`
	ResourceID string `yaml:"resource_id"`
	Reason     string `yaml:"reason"`
	ApprovedBy string `yaml:"approved_by"`
	Expires    string `yaml:"expires"`     // YYYY-MM-DD or empty (never)
	CreatedAt  string `yaml:"created_at"`  // YYYY-MM-DD
}

// SuppressionList is the top-level YAML document.
type SuppressionList struct {
	Suppressions []Suppression `yaml:"suppressions"`
	// Path is the file the list was loaded from (empty if synthesized).
	Path string `yaml:"-"`
}

// LoadSuppressions reads and parses an .argusignore file. A missing
// file is NOT an error — it returns an empty list so the rest of the
// pipeline runs unchanged.
func LoadSuppressions(filePath string) (*SuppressionList, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return &SuppressionList{Suppressions: nil, Path: filePath}, nil
		}
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}

	var list SuppressionList
	if err := yaml.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filePath, err)
	}
	list.Path = filePath

	// Validate every entry. We never reject the whole file for one bad
	// entry — bad entries are logged via Warnings() and excluded from
	// matching. The caller decides how loud to be about them.
	for i := range list.Suppressions {
		s := &list.Suppressions[i]
		s.RuleID = strings.TrimSpace(s.RuleID)
		s.ResourceID = strings.TrimSpace(s.ResourceID)
		if s.ResourceID == "" {
			s.ResourceID = "*"
		}
	}

	return &list, nil
}

// Warnings returns a list of human-readable issues found in the
// suppression list (missing rule_id, expired, etc.). Empty when valid.
func (sl *SuppressionList) Warnings() []string {
	var warnings []string
	now := time.Now().UTC()
	for i, s := range sl.Suppressions {
		if s.RuleID == "" {
			warnings = append(warnings,
				fmt.Sprintf("entry %d: missing rule_id (entire suppression ignored)", i+1))
			continue
		}
		if s.Expires != "" {
			t, err := time.Parse("2006-01-02", s.Expires)
			if err != nil {
				warnings = append(warnings,
					fmt.Sprintf("%s: invalid expires date %q (must be YYYY-MM-DD)", s.RuleID, s.Expires))
				continue
			}
			if t.Before(now) {
				warnings = append(warnings,
					fmt.Sprintf("%s: suppression EXPIRED on %s — finding will appear in main results", s.RuleID, s.Expires))
			} else if t.Sub(now) < 30*24*time.Hour {
				warnings = append(warnings,
					fmt.Sprintf("%s: suppression expires in less than 30 days (%s)", s.RuleID, s.Expires))
			}
		}
	}
	return warnings
}

// IsActive reports whether the suppression is currently in force.
// Expired suppressions return false so the corresponding finding is
// re-surfaced in the main results.
func (s Suppression) IsActive(now time.Time) bool {
	if s.RuleID == "" {
		return false
	}
	if s.Expires == "" {
		return true
	}
	t, err := time.Parse("2006-01-02", s.Expires)
	if err != nil {
		return false
	}
	return !t.Before(now)
}

// IsSuppressed checks whether a finding identified by (ruleID, resourceID)
// matches any active suppression in the list. The returned pointer is
// the matching suppression, or nil if no match.
//
// Matching rules:
//   - rule_id must match exactly (case-sensitive)
//   - resource_id of "*" matches any resource
//   - resource_id with a leading "*/" or trailing "/*" performs a
//     simple wildcard match (only those two anchors are supported)
//   - otherwise resource_id must match exactly (case-insensitive
//     because Azure resource IDs are case-insensitive in practice)
//   - the suppression must be active (not expired)
func (sl *SuppressionList) IsSuppressed(ruleID, resourceID string) (bool, *Suppression) {
	if sl == nil {
		return false, nil
	}
	now := time.Now().UTC()
	for i := range sl.Suppressions {
		s := &sl.Suppressions[i]
		if !s.IsActive(now) {
			continue
		}
		if s.RuleID != ruleID {
			continue
		}
		if matchResource(s.ResourceID, resourceID) {
			return true, s
		}
	}
	return false, nil
}

// matchResource implements the simple wildcard matching for resource IDs.
func matchResource(pattern, target string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	pat := strings.ToLower(pattern)
	tgt := strings.ToLower(target)
	if pat == tgt {
		return true
	}
	if strings.HasPrefix(pat, "*/") && strings.HasSuffix(tgt, pat[1:]) {
		return true
	}
	if strings.HasSuffix(pat, "/*") && strings.HasPrefix(tgt, pat[:len(pat)-1]) {
		return true
	}
	if strings.Contains(pat, "*") {
		// Generic substring containment for any other star location.
		parts := strings.Split(pat, "*")
		idx := 0
		for _, p := range parts {
			if p == "" {
				continue
			}
			j := strings.Index(tgt[idx:], p)
			if j < 0 {
				return false
			}
			idx += j + len(p)
		}
		return true
	}
	return false
}

// FilterFindings splits a finding list into active and suppressed.
// The suppressed slice carries the suppression reason appended to each
// finding's Detail so the report can show context. Findings are
// otherwise unchanged.
func (sl *SuppressionList) FilterFindings(
	findings []models.Finding,
) (active []models.Finding, suppressed []models.Finding) {
	if sl == nil || len(sl.Suppressions) == 0 {
		return findings, nil
	}
	for _, f := range findings {
		matched, sup := sl.IsSuppressed(f.ID, f.ResourceID)
		if !matched {
			active = append(active, f)
			continue
		}
		// Annotate the suppressed copy without mutating the active one.
		fc := f
		annotation := fmt.Sprintf(
			" [SUPPRESSED — reason: %s; approved by: %s",
			sup.Reason, sup.ApprovedBy,
		)
		if sup.Expires != "" {
			annotation += "; expires: " + sup.Expires
		}
		annotation += "]"
		fc.Detail = strings.TrimSpace(fc.Detail) + annotation
		suppressed = append(suppressed, fc)
	}
	return active, suppressed
}

// Append writes a new suppression entry to disk, preserving existing
// entries. Used by the `argus suppress` command.
func Append(filePath string, entry Suppression) error {
	list, err := LoadSuppressions(filePath)
	if err != nil {
		return err
	}
	if entry.CreatedAt == "" {
		entry.CreatedAt = time.Now().UTC().Format("2006-01-02")
	}
	if entry.ResourceID == "" {
		entry.ResourceID = "*"
	}
	list.Suppressions = append(list.Suppressions, entry)

	out, err := yaml.Marshal(list)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	header := []byte("# .argusignore — security findings suppression list\n" +
		"# Documentation: https://github.com/vatsayanvivek/argus#suppressions\n\n")
	if err := os.WriteFile(filePath, append(header, out...), 0644); err != nil {
		return fmt.Errorf("write %s: %w", filePath, err)
	}
	return nil
}
