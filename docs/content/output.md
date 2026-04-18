# Output formats

ARGUS writes the same findings in multiple formats so each consumer gets the right
shape. Pick via `--format <fmt>` or generate all four by running twice.

## HTML report (default)

```bash
argus scan --format html
```

Self-contained single file — no external JS, no CDN, no tracking. Open locally.

**Sections:**

- Executive summary (severity breakdown, top 5 chains, posture score)
- Attack chains (full narrative, step-by-step TTPs)
- Findings table (filter / sort / pivot by pillar, severity, resource)
- Compliance drill-down (per-control pass/fail)
- Raw evidence (collapsible per-finding JSON)

## JSON

```bash
argus scan --format json
```

Stable, versioned schema. Structure:

```json
{
  "scan_id": "01HXB...",
  "scan_time": "2026-04-18T10:22:31Z",
  "subscription_id": "00000000-...",
  "tenant_id": "00000000-...",
  "summary": {
    "critical": 3,
    "high": 12,
    "medium": 41,
    "low": 18
  },
  "findings": [
    {
      "id": "zt_net_001",
      "severity": "CRITICAL",
      "pillar": "Network",
      "resource_id": "/subscriptions/.../nsg/web-nsg",
      "resource_name": "web-nsg",
      "title": "SSH open to the internet",
      "detail": "...",
      "evidence": { ... },
      "compliance_mappings": {
        "soc2": ["CC6.6"],
        "pci-dss-4": ["1.2.1"]
      },
      "participates_in_chains": ["CHAIN-001"]
    }
  ],
  "chains": [
    {
      "id": "CHAIN-001",
      "severity": "CRITICAL",
      "title": "Internet-exposed VM to subscription takeover",
      "narrative": "An attacker scans Azure IP space...",
      "trigger_findings": ["zt_net_001", "zt_wl_001"],
      "steps": [ ... ]
    }
  ]
}
```

Consumers: custom dashboards, SIEM ingest, auditor scripts, `jq` pipelines.

## SARIF

```bash
argus scan --format sarif
```

Standard SARIF 2.1.0. Upload directly to **GitHub code scanning**, **Azure DevOps
code scan**, or any SARIF-compatible tool.

Each rule maps to a SARIF `rule` object with description, help URI, and severity;
each finding maps to a SARIF `result` with location and snippet where possible.

```yaml
# GitHub Actions upload
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: argus-output/argus_*.sarif
```

## Evidence bundle

```bash
argus scan --format evidence
```

Produces a `.zip` with everything — HTML, JSON, SARIF, plus per-rule raw evidence
and a manifest. Designed for auditor hand-off. See [Compliance](compliance.md#evidence-bundle)
for the full manifest.

## Multiple formats in one run

```bash
argus scan \
  --format html,json,sarif \
  --out ./argus-output
```

Each format is written to a separate file in the output directory.

## Severity filtering

```bash
# Only CRITICAL + HIGH in the report
argus scan --min-severity HIGH
```

Applied before rendering so downstream consumers don't see filtered-out findings.

## Output location

Default: `./argus-output/argus_<timestamp>.<ext>`

Override: `--out <dir>`

Timestamped filenames let you run multiple scans without overwriting prior reports —
useful for `argus diff` and historical comparison.
