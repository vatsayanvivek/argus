// Command gendocs walks the Rego policy tree and the chain correlator and
// emits one Markdown page per rule and per chain for the MkDocs site.
//
//   go run ./cmd/gendocs
//
// Outputs:
//   docs/content/rules/<rule-id>.md       (per-rule page)
//   docs/content/rules/index.md           (catalog index)
//   docs/content/chains/<chain-id>.md     (per-chain page)
//   docs/content/chains/index.md          (catalog index)
//
// The generator is stateless — running it is safe, idempotent, and fast.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"

	"github.com/vatsayanvivek/argus/internal/engine"
	"github.com/vatsayanvivek/argus/internal/models"
)

type ruleMeta struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Pillar         string   `json:"pillar"`
	ZTTenet        string   `json:"zt_tenet"`
	NIST80053      string   `json:"nist_800_53"`
	NIST800207     string   `json:"nist_800_207"`
	CISRule        string   `json:"cis_rule"`
	MITRETechnique string   `json:"mitre_technique"`
	MITRETactic    string   `json:"mitre_tactic"`
	ChainRole      string   `json:"chain_role"`
	Frameworks     []string `json:"frameworks"`
	Source         string   `json:"source"`
	Path           string   // rego file path (relative to repo root)
}

// -----------------------------------------------------------------------------
// Rule catalog
// -----------------------------------------------------------------------------

func loadRuleMetadata(policyRoot string) ([]ruleMeta, error) {
	var out []ruleMeta
	err := filepath.Walk(policyRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(p, ".rego") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		mod, err := ast.ParseModule(p, string(src))
		if err != nil || mod == nil {
			return nil
		}
		meta, ok := extractMetadata(mod)
		if !ok || meta.ID == "" {
			return nil
		}
		rel, rerr := filepath.Rel(".", p)
		if rerr == nil {
			meta.Path = filepath.ToSlash(rel)
		}
		out = append(out, meta)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

func extractMetadata(mod *ast.Module) (ruleMeta, bool) {
	for _, rule := range mod.Rules {
		if rule.Head == nil || string(rule.Head.Name) != "metadata" {
			continue
		}
		val, err := termToJSON(rule.Head.Value)
		if err != nil {
			continue
		}
		raw, _ := json.Marshal(val)
		var m ruleMeta
		if err := json.Unmarshal(raw, &m); err == nil && m.ID != "" {
			return m, true
		}
	}
	return ruleMeta{}, false
}

func termToJSON(t *ast.Term) (interface{}, error) {
	if t == nil {
		return nil, fmt.Errorf("nil term")
	}
	return valueToJSON(t.Value)
}

func valueToJSON(v ast.Value) (interface{}, error) {
	switch t := v.(type) {
	case ast.Null:
		return nil, nil
	case ast.Boolean:
		return bool(t), nil
	case ast.Number:
		return json.Number(string(t)), nil
	case ast.String:
		return string(t), nil
	case *ast.Array:
		out := make([]interface{}, 0, t.Len())
		var e error
		t.Foreach(func(x *ast.Term) {
			if e != nil {
				return
			}
			iv, err := termToJSON(x)
			if err != nil {
				e = err
				return
			}
			out = append(out, iv)
		})
		return out, e
	case ast.Object:
		out := make(map[string]interface{}, t.Len())
		var e error
		t.Foreach(func(k, val *ast.Term) {
			if e != nil {
				return
			}
			ks, ok := k.Value.(ast.String)
			if !ok {
				e = fmt.Errorf("non-string key")
				return
			}
			iv, err := termToJSON(val)
			if err != nil {
				e = err
				return
			}
			out[string(ks)] = iv
		})
		return out, e
	}
	return v.String(), nil
}

// -----------------------------------------------------------------------------
// Rule pages
// -----------------------------------------------------------------------------

func emitRulePages(rules []ruleMeta, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, r := range rules {
		p := filepath.Join(outDir, r.ID+".md")
		body := renderRulePage(r)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func renderRulePage(r ruleMeta) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n\n", r.ID, mdEscape(r.Title))
	fmt.Fprintf(&b, "!!! note \"Summary\"\n    **Severity:** %s · **Pillar:** %s · **Chain role:** %s\n\n",
		badgeSeverity(r.Severity), nonEmpty(r.Pillar, "—"), nonEmpty(r.ChainRole, "—"))
	fmt.Fprintf(&b, "## Description\n\n%s\n\n", mdEscape(r.Description))

	fmt.Fprintf(&b, "## Mapping\n\n")
	fmt.Fprintf(&b, "| Framework | Control / Reference |\n|---|---|\n")
	fmt.Fprintf(&b, "| NIST 800-53 | %s |\n", nonEmpty(r.NIST80053, "—"))
	fmt.Fprintf(&b, "| NIST 800-207 | %s |\n", nonEmpty(r.NIST800207, "—"))
	fmt.Fprintf(&b, "| CIS Azure | %s |\n", nonEmpty(r.CISRule, "—"))
	fmt.Fprintf(&b, "| MITRE ATT&CK Technique | %s |\n", nonEmpty(r.MITRETechnique, "—"))
	fmt.Fprintf(&b, "| MITRE ATT&CK Tactic | %s |\n", nonEmpty(r.MITRETactic, "—"))
	fmt.Fprintf(&b, "| Zero-Trust Tenet | %s |\n", nonEmpty(r.ZTTenet, "—"))
	if len(r.Frameworks) > 0 {
		fmt.Fprintf(&b, "| Framework tags | %s |\n", strings.Join(r.Frameworks, ", "))
	}
	fmt.Fprintln(&b)

	fmt.Fprintf(&b, "## Source\n\nRule defined at `%s`.\n\n", r.Path)
	fmt.Fprintf(&b, "[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/%s){ .md-button }\n", r.Path)
	return b.String()
}

func emitRuleIndex(rules []ruleMeta, outDir string) error {
	var b strings.Builder
	b.WriteString("# Rule catalog\n\n")
	b.WriteString(fmt.Sprintf("ARGUS ships **%d Rego rules** organised by zero-trust pillar. Each rule carries NIST 800-53, MITRE ATT&CK, and framework-tag metadata used for compliance mapping and reporting.\n\n", len(rules)))
	b.WriteString("Use your browser's search (Ctrl/Cmd+F) or the search box above to find a specific rule ID or keyword.\n\n")

	// Group by pillar.
	byPillar := map[string][]ruleMeta{}
	for _, r := range rules {
		p := r.Pillar
		if p == "" {
			p = "Other"
		}
		byPillar[p] = append(byPillar[p], r)
	}
	pillars := make([]string, 0, len(byPillar))
	for p := range byPillar {
		pillars = append(pillars, p)
	}
	sort.Strings(pillars)

	for _, p := range pillars {
		list := byPillar[p]
		fmt.Fprintf(&b, "## %s (%d rules)\n\n", p, len(list))
		b.WriteString("| ID | Title | Severity | Chain role |\n|---|---|---|---|\n")
		for _, r := range list {
			fmt.Fprintf(&b, "| [%s](%s.md) | %s | %s | %s |\n",
				r.ID, r.ID, mdEscape(r.Title), badgeSeverity(r.Severity), nonEmpty(r.ChainRole, "—"))
		}
		b.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(outDir, "index.md"), []byte(b.String()), 0o644)
}

// -----------------------------------------------------------------------------
// Chain catalog
// -----------------------------------------------------------------------------

type chainMeta struct {
	ID       string
	Logic    string
	Triggers []string
	Anchor   string
	Example  *models.AttackChain // full chain data from running the builder
}

// parseChainsFromCorrelator parses internal/engine/correlator.go and extracts
// the ChainPattern entries. We use a lightweight regex pass rather than go/ast
// to avoid pulling in the typechecker — the struct literal format is stable
// and easy to match.
func parseChainsFromCorrelator(path string) ([]chainMeta, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Each chain is registered as a struct literal. We split on "ID:" and
	// walk each block. Example:
	//   ID:           "CHAIN-001",
	//   TriggerLogic: "ANCHOR_PLUS_ONE",
	//   AnchorID:     "zt_net_001",
	//   TriggerIDs:   []string{"zt_net_001", "zt_net_002", ...},
	blockRe := regexp.MustCompile(`(?s)ID:\s*"(CHAIN-\d+)",\s*` +
		`TriggerLogic:\s*"([A-Z_]+)",.*?` +
		`TriggerIDs:\s*\[\]string\{([^}]+)\}`)
	anchorRe := regexp.MustCompile(`AnchorID:\s*"([a-z0-9_]+)"`)
	ruleIDRe := regexp.MustCompile(`"([a-z0-9_]+)"`)

	matches := blockRe.FindAllStringSubmatchIndex(string(src), -1)
	out := make([]chainMeta, 0, len(matches))
	for _, m := range matches {
		id := string(src[m[2]:m[3]])
		logic := string(src[m[4]:m[5]])
		triggersRaw := string(src[m[6]:m[7]])
		// Look for an AnchorID within the same block (between m[0] and m[1]).
		block := string(src[m[0]:m[1]])
		anchor := ""
		if a := anchorRe.FindStringSubmatch(block); len(a) == 2 {
			anchor = a[1]
		}
		triggers := []string{}
		for _, t := range ruleIDRe.FindAllStringSubmatch(triggersRaw, -1) {
			triggers = append(triggers, t[1])
		}
		out = append(out, chainMeta{ID: id, Logic: logic, Triggers: triggers, Anchor: anchor})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func emitChainPages(chains []chainMeta, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, c := range chains {
		p := filepath.Join(outDir, c.ID+".md")
		body := renderChainPage(c)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func renderChainPage(c chainMeta) string {
	var b strings.Builder
	title := c.ID
	if c.Example != nil && c.Example.Title != "" {
		title = fmt.Sprintf("%s — %s", c.ID, c.Example.Title)
	}
	fmt.Fprintf(&b, "# %s\n\n", title)

	if c.Example != nil {
		severity := c.Example.Severity
		likelihood := c.Example.Likelihood
		fmt.Fprintf(&b, "!!! note \"Summary\"\n    **Severity:** %s · **Likelihood:** %s · **Logic:** `%s`",
			badgeSeverity(severity), nonEmpty(likelihood, "—"), c.Logic)
	} else {
		fmt.Fprintf(&b, "!!! note \"Trigger logic\"\n    **Logic:** `%s`", c.Logic)
	}
	if c.Anchor != "" {
		fmt.Fprintf(&b, " · **Anchor:** [`%s`](../rules/%s.md)", c.Anchor, c.Anchor)
	}
	b.WriteString("\n\n")

	if c.Example != nil && c.Example.Narrative != "" {
		b.WriteString("## Why this chain matters\n\n")
		b.WriteString(c.Example.Narrative)
		b.WriteString("\n\n")
	}

	b.WriteString("## Component rules\n\n")
	b.WriteString("This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.\n\n")
	b.WriteString("| Rule ID | Role |\n|---|---|\n")
	for _, r := range c.Triggers {
		role := "Trigger"
		if r == c.Anchor {
			role = "**Anchor**"
		}
		fmt.Fprintf(&b, "| [`%s`](../rules/%s.md) | %s |\n", r, r, role)
	}
	b.WriteString("\n")

	if c.Example != nil && len(c.Example.Steps) > 0 {
		b.WriteString("## Attack walkthrough\n\n")
		for _, s := range c.Example.Steps {
			fmt.Fprintf(&b, "### Step %d — %s\n\n", s.Number, mdEscape(s.Action))
			if s.Actor != "" {
				fmt.Fprintf(&b, "**Actor:** %s  \n", s.Actor)
			}
			if s.Technique != "" {
				fmt.Fprintf(&b, "**MITRE ATT&CK:** `%s`  \n", s.Technique)
			}
			if s.EnabledBy != "" {
				fmt.Fprintf(&b, "**Enabled by:** [`%s`](../rules/%s.md)  \n", s.EnabledBy, s.EnabledBy)
			}
			if s.Technical != "" {
				fmt.Fprintf(&b, "\n> %s\n", s.Technical)
			}
			if s.Gain != "" {
				fmt.Fprintf(&b, "\n**Attacker gain:** %s\n\n", s.Gain)
			}
			b.WriteString("\n")
		}
	}

	if c.Example != nil {
		br := c.Example.BlastRadius
		if br.InitialAccess != "" || br.MaxPrivilege != "" {
			b.WriteString("## Blast radius\n\n")
			b.WriteString("| | |\n|---|---|\n")
			if br.InitialAccess != "" {
				fmt.Fprintf(&b, "| Initial access | %s |\n", mdEscape(br.InitialAccess))
			}
			if br.LateralMovement != "" {
				fmt.Fprintf(&b, "| Lateral movement | %s |\n", mdEscape(br.LateralMovement))
			}
			if br.MaxPrivilege != "" {
				fmt.Fprintf(&b, "| Max privilege | %s |\n", mdEscape(br.MaxPrivilege))
			}
			if len(br.DataAtRisk) > 0 {
				fmt.Fprintf(&b, "| Data at risk | %s |\n", strings.Join(br.DataAtRisk, ", "))
			}
			if len(br.ServicesAtRisk) > 0 {
				fmt.Fprintf(&b, "| Services at risk | %s |\n", strings.Join(br.ServicesAtRisk, ", "))
			}
			if br.EstimatedScopePerc != "" {
				fmt.Fprintf(&b, "| Estimated scope | %s |\n", mdEscape(br.EstimatedScopePerc))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## How the logic works\n\n")
	switch c.Logic {
	case "ALL":
		b.WriteString("The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.\n")
	case "ANY_TWO":
		b.WriteString("The chain fires when **at least two** of the rules above have findings. The blast radius depends on which two fire; consult the per-rule mitigations to pick the cheapest one to remediate first.\n")
	case "ANCHOR_PLUS_ONE":
		b.WriteString("The chain fires when the **anchor** rule fires AND at least one of the other triggers fires. The anchor represents the initial foothold; the second rule amplifies it into a meaningful attack. Remediate the anchor to eliminate the entire chain.\n")
	}
	b.WriteString("\n")
	return b.String()
}

func emitChainIndex(chains []chainMeta, outDir string) error {
	var b strings.Builder
	b.WriteString("# Attack chains\n\n")
	fmt.Fprintf(&b, "ARGUS ships **%d attack chains** — realistic, multi-step attack narratives that correlate individual findings into end-to-end paths. A chain fires only when real findings in your scan match its trigger pattern, so the output reads like an incident write-up, not a checklist.\n\n", len(chains))

	b.WriteString("## Trigger logic reference\n\n")
	b.WriteString("| Logic | Meaning |\n|---|---|\n")
	b.WriteString("| `ALL` | Every rule in the trigger set must fire. |\n")
	b.WriteString("| `ANY_TWO` | At least two rules in the trigger set must fire. |\n")
	b.WriteString("| `ANCHOR_PLUS_ONE` | The anchor rule must fire AND at least one other trigger. |\n\n")

	b.WriteString("## Chain list\n\n")
	b.WriteString("| ID | Logic | Triggers | Anchor |\n|---|---|---|---|\n")
	for _, c := range chains {
		anchor := "—"
		if c.Anchor != "" {
			anchor = "`" + c.Anchor + "`"
		}
		fmt.Fprintf(&b, "| [%s](%s.md) | `%s` | %d | %s |\n",
			c.ID, c.ID, c.Logic, len(c.Triggers), anchor)
	}
	return os.WriteFile(filepath.Join(outDir, "index.md"), []byte(b.String()), 0o644)
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func badgeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return ":material-alert-octagon: Critical"
	case "HIGH":
		return ":material-alert: High"
	case "MEDIUM":
		return ":material-alert-circle-outline: Medium"
	case "LOW":
		return ":material-information-outline: Low"
	}
	return s
}

var mdEscapeRe = regexp.MustCompile(`([_*\[\]\\])`)

func mdEscape(s string) string {
	// Just escape characters that break markdown table rendering.
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

func main() {
	rules, err := loadRuleMetadata("policies")
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	if len(rules) == 0 {
		log.Fatalf("no rules found — run from repo root")
	}

	rulesOut := "docs/content/rules"
	if err := emitRulePages(rules, rulesOut); err != nil {
		log.Fatalf("emit rule pages: %v", err)
	}
	if err := emitRuleIndex(rules, rulesOut); err != nil {
		log.Fatalf("emit rule index: %v", err)
	}

	// Source both hand-coded chains (from Go regex parse of correlator.go
	// — gives us Anchor info for ANCHOR_PLUS_ONE) and data-driven chains
	// (from NewCorrelator().ExampleChains() which covers both sets).
	regexChains, err := parseChainsFromCorrelator("internal/engine/correlator.go")
	if err != nil {
		log.Fatalf("parse chains: %v", err)
	}
	regexByID := map[string]chainMeta{}
	for _, c := range regexChains {
		regexByID[c.ID] = c
	}

	examples := engine.NewCorrelator().ExampleChains()
	chains := make([]chainMeta, 0, len(examples))
	for i := range examples {
		ex := examples[i]
		meta := chainMeta{
			ID:       ex.ID,
			Logic:    ex.TriggerLogic,
			Triggers: append([]string(nil), ex.TriggerFindings...),
			Example:  &ex,
		}
		if rc, ok := regexByID[ex.ID]; ok {
			meta.Anchor = rc.Anchor
			// Prefer regex-sourced Triggers since ExampleChains returns
			// TriggerFindings which is the list actually present — not
			// the full TriggerIDs the pattern is interested in.
			if len(rc.Triggers) > len(meta.Triggers) {
				meta.Triggers = rc.Triggers
			}
		}
		chains = append(chains, meta)
	}
	sort.Slice(chains, func(i, j int) bool { return chains[i].ID < chains[j].ID })
	chainsOut := "docs/content/chains"
	if err := emitChainPages(chains, chainsOut); err != nil {
		log.Fatalf("emit chain pages: %v", err)
	}
	if err := emitChainIndex(chains, chainsOut); err != nil {
		log.Fatalf("emit chain index: %v", err)
	}

	fmt.Printf("Wrote %d rule pages and %d chain pages.\n", len(rules), len(chains))
	_ = mdEscapeRe // keep in scope for future use
}
