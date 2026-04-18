# CHAIN-159 — Service Bus SAS-only auth + key sprawl

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Service Bus namespace uses only SAS policies (no Entra ID integration). The RootManageSharedAccessKey is shared across CI, apps, and developer laptops. A leaked key gives full send/receive on every queue and topic.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_004`](../rules/zt_int_004.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Harvest RootManageSharedAccessKey from CI env var.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_int_004`](../rules/zt_int_004.md)  

**Attacker gain:** Valid Service Bus master key.


### Step 2 — Read every queue; inject malicious messages.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Message bus poisoning + message content exfil.


## Blast radius

| | |
|---|---|
| Initial access | Leaked key. |
| Max privilege | Namespace-wide SAS. |
| Data at risk | Every queue / topic message |
| Services at risk | Service Bus + consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

