# FAQ

## General

**Is ARGUS open source?**
Source-available under PolyForm Strict 1.0.0. You can read, audit, and run every line.
You cannot fork or redistribute.

**Is it free?**
Yes. Completely free. No artificial limits, no "scan up to N resources" gate, no paywall.

**Will it always be free?**
The core scanner, all rules, all chains, local dashboard, VSCode extension, and compliance
packs will stay free forever. Future paid tiers exist for enterprise operational features
(SSO, ticketing integrations, air-gap deployment support) — never for scanning capability.

**How do I report a bug?**
[Open an issue](https://github.com/vatsayanvivek/argus/issues). Security issues: see
[SECURITY.md](https://github.com/vatsayanvivek/argus/blob/main/SECURITY.md).

## Scan behaviour

**How long does a scan take?**
Depends on subscription size. Typical:

| Subscription size | Scan time |
|---|---|
| Small (< 100 resources) | 15-30 s |
| Medium (100-1000) | 1-3 min |
| Large (1000-10000) | 3-10 min |
| Very large (10000+) | 10-30 min |

Entra ID collection dominates for tenants with many users / service principals.

**Does ARGUS send data to Anthropic / AWS / anyone?**
No. Zero network calls except to Azure management, ARM, and Microsoft Graph APIs —
and those only while actively scanning. No analytics, telemetry, crash reporting,
update pings, or license checks. The binary works fully offline against IaC.

**Does it write to my Azure environment?**
Read-only. Every Azure SDK call uses a read-only RBAC role. You can use a scoped-down
`Reader` + `Security Reader` principal for ARGUS.

**What permissions does ARGUS need?**
Minimum:

- Azure RBAC: `Reader` at subscription scope
- Defender: `Security Reader`
- Microsoft Graph: `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`,
  `PrivilegedAccess.Read.AzureAD` (for PIM)

Run `argus check-permissions` to probe your actual scopes before scanning.

**Why did my scan say "Limited Microsoft Graph Access"?**
Some Graph endpoints returned 401/403. The scan completed but a few identity-related
checks (notably App Registration takeover, PIM, conditional access) couldn't run.
Download `setup-graph-permissions.sh` (or `.ps1`) from the latest release to grant the
missing scopes.

**Can I run it offline / air-gapped?**
Yes for IaC scans: `argus scan --iac-only --iac-path ./infra`. For live Azure scans
the scanner must reach Azure management APIs.

## Windows-specific

**Windows Defender / SmartScreen says "Unknown publisher."**
Binaries aren't code-signed yet — code-signing is gated on budget. Your options:

1. Verify the SHA-256 against `SHA256SUMS` in the release, then click "More info → Run anyway."
2. Verify the cosign signature (see [Trust](trust.md)).
3. Wait for the signed release (roadmap).

This is not a security defect — the binary is fine. SmartScreen flags **any** unsigned
EXE regardless of content. See [Trust](trust.md) for how to verify independently.

**Does it work in PowerShell?**
Yes — both PowerShell and cmd.exe. The setup helper script ships in both `.sh` (bash)
and `.ps1` (PowerShell) forms.

## Development & extension

**Can I write my own rules?**
Rules live at `policies/azure/zt/<category>/<rule-id>.rego`. The engine auto-loads every
`.rego` file it finds with a valid `metadata` block. Rego knowledge required — see the
[OPA Rego docs](https://www.openpolicyagent.org/docs/latest/policy-language/).

Tier B ships `argus rule new <name>` to scaffold a new rule with tests.

**Can I modify existing rules?**
Source-available license permits reading and running but not redistributing modified
versions. If you need a custom rule, add a new file rather than editing a shipped rule.

**How do I add a new compliance pack?**
Drop a JSON file into `policies/compliance/<framework>.json` with the mapping table.
The engine picks it up at startup. No rebuild needed if you run from source; for binary
users, the pack must be embedded (tracked for Tier B).

## Output

**Can I generate multiple report formats at once?**
```bash
argus scan --format html,json,sarif
```

**Where are reports saved?**
Default `./argus-output/argus_<timestamp>.<ext>`. Override with `--out <dir>`.

**Do findings persist across scans?**
Each scan writes a new timestamped file. `argus diff` (Tier A5) compares two scans and
shows added / resolved findings between them.

## Comparison

**How does ARGUS compare to Checkov / Trivy / tfsec?**
Those are IaC-only. ARGUS scans IaC **and** live Azure **and** correlates findings into
attack chains. They don't.

**How does it compare to Defender for Cloud / Wiz / Prisma Cloud?**
Those are SaaS — they require data egress to the vendor's cloud. ARGUS runs entirely in
your environment. You own the data.

**Should I use ARGUS instead of Wiz?**
Use ARGUS if: you want auditable rules, air-gap support, zero data egress, low / no cost,
or Azure-focused coverage.
Use Wiz if: you need multi-cloud + agents + ML-based prioritisation + a dedicated CSM +
have the budget for all of that.
They can coexist.

## Licensing

**Can I redistribute ARGUS?**
No. PolyForm Strict prohibits redistribution.

**Can I use ARGUS output in a customer deliverable?**
Yes — the output (HTML, JSON, SARIF reports) is yours. The license restricts the binary,
not what you produce with it.

**Can I run ARGUS on customer environments as a consultant?**
Yes, using your own licensed copy.

**Can I charge for a managed-ARGUS service?**
No — that's redistribution of the binary-as-a-service. Build your own tool, or contact
us for a commercial license.
