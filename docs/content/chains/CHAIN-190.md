# CHAIN-190 — Critical resources without resource locks

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Production storage accounts, key vaults, and databases have no delete locks. A compromised Contributor or an accidental 'rm -rf' via Terraform can destroy them in seconds — with no two-step confirmation.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_007`](../rules/zt_vis_007.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Terraform destroy or Portal delete on unlocked resource.

**Actor:** Attacker / accident  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_vis_007`](../rules/zt_vis_007.md)  

**Attacker gain:** Unrecoverable deletion.


### Step 2 — Extended outage; potential data loss depending on backup state.

**Actor:** Organisation  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Operational damage.


## Blast radius

| | |
|---|---|
| Initial access | Contributor or automation bug. |
| Max privilege | Destructive resource deletion. |
| Data at risk | Any resource without a lock |
| Services at risk | Every unlocked critical resource |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

