# CHAIN-103 — Private DNS zone hijack via delegation

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Private DNS zones are linked to VNets without strict IAM. An attacker with Private DNS Zone Contributor creates a CNAME for an internal service name to attacker-controlled storage, harvesting internal traffic intended for legitimate endpoints.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_022`](../rules/zt_net_022.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Add CNAME internal-api -> attacker.blob.core.windows.net.

**Actor:** Attacker with DNS write  
**MITRE ATT&CK:** `T1584.002`  
**Enabled by:** [`zt_net_022`](../rules/zt_net_022.md)  

**Attacker gain:** DNS-based MITM in private plane.


### Step 2 — Resolves internal-api to attacker storage; sends auth tokens in request headers.

**Actor:** Victim app  
**MITRE ATT&CK:** `T1557`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Captured bearer tokens.


## Blast radius

| | |
|---|---|
| Initial access | Private DNS write. |
| Max privilege | Token capture + future replay. |
| Data at risk | Any internal service bearer tokens |
| Services at risk | Every VNet-linked DNS consumer |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

