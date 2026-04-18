# CHAIN-098 — Immutability lock too short for retention requirements

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Blob immutability policy is set but retention is shorter than required retention (e.g. 30 days when SOX requires 7 years). Auditors flag this as a compliance gap; operationally, the window during which data can be deleted is earlier than expected.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_020`](../rules/zt_data_020.md) | Trigger |
| [`zt_data_016`](../rules/zt_data_016.md) | Trigger |

## Attack walkthrough

### Step 1 — Immutability window expires; blobs become deletable.

**Actor:** Compliance finding  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_020`](../rules/zt_data_020.md)  

**Attacker gain:** Premature deletion eligibility.


### Step 2 — Delete or overwrite; pre-retention-period exposure.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_data_016`](../rules/zt_data_016.md)  

**Attacker gain:** Data destruction before audit retention met.


## Blast radius

| | |
|---|---|
| Initial access | Any WRITE role. |
| Max privilege | Destructive during early window. |
| Data at risk | Blobs under too-short lock |
| Services at risk | Regulated data store |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

