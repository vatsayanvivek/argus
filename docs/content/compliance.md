# Compliance packs

ARGUS maps **every** rule to four compliance frameworks at 100% coverage. When you run
a pack filter, only rules tagged for that framework evaluate — and every finding carries
the control IDs it satisfies.

| Framework | Rules mapped | Coverage |
|---|---|---|
| **SOC 2** | 245 / 245 | 100% |
| **HIPAA** | 245 / 245 | 100% |
| **PCI DSS 4.0** | 245 / 245 | 100% |
| **ISO 27001:2022** | 245 / 245 | 100% |

## Running a pack

```bash
# SOC 2 only
argus scan --compliance soc2

# HIPAA only
argus scan --compliance hipaa

# PCI DSS 4.0
argus scan --compliance pci-dss-4

# ISO 27001:2022
argus scan --compliance iso-27001
```

The HTML report gets a dedicated "Compliance" tab with:

- Overall pass / fail posture by control
- Per-control drill-down (which resources are in-scope, which fail, why)
- Evidence for every passing and failing control
- PDF-ready printable view for your auditor

## Evidence bundle

For regulated environments, use `--format evidence`:

```bash
argus scan --compliance soc2 --format evidence
```

This produces a `.zip` containing:

- The full HTML report
- The raw JSON findings
- SARIF for code scanning integration
- Per-rule raw configuration evidence (one JSON per failing rule)
- A manifest listing every control + its evidence file
- SHA-256 checksums for every artifact in the bundle

Hand this directly to your auditor. The manifest + checksums are designed to satisfy
SOC 2 CC7.x and ISO 27001 A.12.x evidence requirements.

## Control mapping source

Compliance packs live at [`policies/compliance/*.json`][packs]. Each pack is:

```json
{
  "framework": "soc2",
  "mappings": {
    "zt_id_001": ["CC6.1", "CC6.2"],
    "zt_net_001": ["CC6.6"],
    ...
  }
}
```

They're loaded by the engine at startup. Want your own pack (FedRAMP, CMMC, DORA, your
internal framework)? Drop a JSON file into `policies/compliance/` and it's loaded
automatically. The engine warns if a mapping references an unknown rule ID.

[packs]: https://github.com/vatsayanvivek/argus/tree/main/policies/compliance

## Why 100% mapping matters

Most scanners ship with partial compliance mappings — "we check 70% of SOC 2, figure
out the rest yourself." ARGUS maps every rule to every framework because:

1. **Auditors want completeness.** Partial mappings make them question the tool.
2. **Gap analysis is the value.** If a control has zero mapped rules, that's a signal —
   either ARGUS needs a new rule or the control needs a manual attestation.
3. **Maintenance.** Adding a rule without mapping it to packs is a regression the CI
   tests catch.
