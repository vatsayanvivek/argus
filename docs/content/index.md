---
hide:
  - navigation
  - toc
---

# ARGUS

**Agentless, offline Azure CSPM + attack-chain analysis.**
Your data never leaves your environment. Your rules are auditable. You own everything.

<div class="grid cards" markdown>

- :material-rocket-launch: **[Get started in 60 seconds](install.md)**
  Download a binary, run one command, see your Azure posture.

- :material-shield-search: **[245 Rego rules](rules/index.md)**
  Browse every check ARGUS performs, mapped to NIST 800-53, MITRE ATT&CK, and four compliance frameworks.

- :material-graph: **[51 attack chains](chains/index.md)**
  Realistic, end-to-end attack narratives — not just lists of findings.

- :material-lock-check: **[Trust & verification](trust.md)**
  SLSA build provenance, cosign signatures, SPDX SBOM, CVE scan — how to verify every artifact.

</div>

## Why ARGUS

Most cloud security scanners send your environment data to someone else's SaaS. ARGUS is a
single binary that runs in **your** pipeline, your laptop, or your air-gapped network — and
writes its report to **your** filesystem. It never phones home.

!!! quote "Positioning"
    Wiz is a dashboard that phones home. ARGUS is a scanner that ships in your pipeline and
    a dashboard you run yourself. **Same findings. Your data. Your rules. Your environment.**

## What makes it different

| | ARGUS | Typical CSPM SaaS |
|---|---|---|
| Runs in your environment | :material-check: | :material-close: |
| No data egress | :material-check: | :material-close: |
| Open, auditable rules | :material-check: Rego | :material-close: black box |
| Attack-chain analysis | :material-check: 51 chains | Limited |
| Compliance packs | :material-check: SOC 2 / HIPAA / PCI / ISO | Paid tier |
| Air-gap support | :material-check: | :material-close: |
| Price | Free (OSS) | $50K+/yr |

## Works everywhere

<div class="grid cards" markdown>

- :material-microsoft-windows: **Windows**
  Single `.exe` — no runtime dependencies.

- :material-apple: **macOS**
  Intel + Apple Silicon binaries.

- :material-linux: **Linux**
  amd64 + arm64 binaries, one-line install.

- :material-docker: **Docker**
  Hardened Chainguard base, SLSA-provenanced.

</div>

## Coverage at a glance

- **Identity** — Entra ID, Conditional Access, PIM, Service Principals, App Registrations
- **Data** — Storage, SQL, Cosmos DB, Key Vault, Data Lake, Databricks, Synapse
- **Network** — NSGs, VNets, Private Endpoints, VPN, ExpressRoute, Front Door
- **Compute** — VMs, VMSS, AKS, App Service, Function Apps, Container Apps
- **AI / ML** — Azure OpenAI, Cognitive Services, ML Workspace
- **Integration** — API Management, Event Grid, Service Bus, Logic Apps, Traffic Manager
- **Observability** — Defender for Cloud, Activity Log, Diagnostic Settings, Sentinel
- **Key Management** — Key Vault rotation, HSM, certificate lifecycle
- **Backup** — Recovery Services Vault immutability, CRR, retention
- **DevOps** — ARM / Bicep / Terraform IaC scanning

[Get started :material-arrow-right:](install.md){ .md-button .md-button--primary }
[See the rule catalog :material-arrow-right:](rules/index.md){ .md-button }
