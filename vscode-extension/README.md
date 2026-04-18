# ARGUS IaC Scanner

Inline Azure CSPM and attack-chain findings for your **Bicep**, **ARM**, and
**Terraform** files — powered by [ARGUS](https://github.com/vatsayanvivek/argus).

Everything runs locally. **Nothing leaves your machine.**

## What it does

- On save, scans the workspace's IaC files against **245 Rego rules** and
  **200 attack chains**
- Inline diagnostics in the editor (red = CRITICAL/HIGH, yellow = MEDIUM,
  blue = LOW)
- Click a rule ID to open its page in the ARGUS docs
- Status bar shows the live finding count

## Requirements

- The `argus` binary on your `PATH`
  ([install from releases](https://github.com/vatsayanvivek/argus/releases/latest))
  or configure `argus.binaryPath` to a specific path.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `argus.binaryPath` | `argus` | Path to the argus binary |
| `argus.scanOnSave` | `true` | Rescan when an IaC file is saved |
| `argus.minSeverity` | `LOW` | Lowest severity to show |
| `argus.complianceFilter` | (none) | Restrict to a compliance pack (`soc2`, `hipaa`, `pci-dss-4`, `iso-27001`) |

## Commands

- **ARGUS: Scan current workspace (IaC only)**
- **ARGUS: Scan this file**
- **ARGUS: Clear diagnostics**

## Privacy

This extension never makes a network call. It invokes the local `argus`
binary, reads the JSON it produces, and converts it to VSCode diagnostics.
