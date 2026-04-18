# CHAIN-183 — Diagnostic settings missing on Key Vault

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A Key Vault has no diagnostic settings streaming to a SIEM. AccessPolicyChange and SecretGet events are invisible to defenders. An attacker with vault read can enumerate every secret and the security team never sees it.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |
| [`zt_vis_011`](../rules/zt_vis_011.md) | Trigger |

## Attack walkthrough

### Step 1 — List and read every secret; each GetSecret logs only in vault itself.

**Actor:** Attacker with reader  
**MITRE ATT&CK:** `T1552`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Bulk secret exfiltration.


### Step 2 — Clean up vault-local logs (if retention config allows).

**Actor:** Attacker  
**MITRE ATT&CK:** `T1070`  
**Enabled by:** [`zt_vis_011`](../rules/zt_vis_011.md)  

**Attacker gain:** No trace of the exfiltration.


## Blast radius

| | |
|---|---|
| Initial access | Vault reader. |
| Max privilege | Silent full vault read. |
| Data at risk | Every secret/key/cert |
| Services at risk | Anything protected by the vault |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

