# CHAIN-065 — Overprivileged device registration lets attacker bypass CA

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Device registration is not restricted — any user in the tenant can register a new device. An attacker registers their attacker-controlled laptop as a 'compliant' device, then uses device-bound refresh tokens to satisfy the 'compliant device' Conditional Access requirement.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_020`](../rules/zt_id_020.md) | Trigger |
| [`zt_id_007`](../rules/zt_id_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Register their laptop as a tenant device.

**Actor:** Attacker with stolen creds  
**MITRE ATT&CK:** `T1098.005`  
**Enabled by:** [`zt_id_020`](../rules/zt_id_020.md)  

**Attacker gain:** Fake-compliant device object.


### Step 2 — Obtain PRT; use it to bypass CA policies that require compliant device.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1550.001`  
**Enabled by:** [`zt_id_007`](../rules/zt_id_007.md)  

**Attacker gain:** Full session access to protected apps.


## Blast radius

| | |
|---|---|
| Initial access | Stolen corporate creds. |
| Max privilege | User level + CA bypass. |
| Data at risk | User's protected-app data (Teams, SharePoint, Exchange) |
| Services at risk | Entra device trust |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

