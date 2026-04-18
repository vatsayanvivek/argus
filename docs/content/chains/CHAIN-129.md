# CHAIN-129 — VMSS custom image drift — older CVE-prone version

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

VMSS uses a custom image built 18 months ago. New instances boot with the same stale OS and package versions. The fleet drifts from 'golden image' security posture over time, silently accumulating exploitable CVEs.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_015`](../rules/zt_wl_015.md) | Trigger |
| [`zt_wl_029`](../rules/zt_wl_029.md) | Trigger |

## Attack walkthrough

### Step 1 — CVE-2024-xxxx published; image is affected.

**Actor:** Time  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_015`](../rules/zt_wl_015.md)  

**Attacker gain:** Public exploit for stale image.


### Step 2 — Attack the fleet; every instance vulnerable.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1210`  
**Enabled by:** [`zt_wl_029`](../rules/zt_wl_029.md)  

**Attacker gain:** Fleet compromise.


## Blast radius

| | |
|---|---|
| Initial access | Public exploit. |
| Max privilege | Root on VMSS instances. |
| Data at risk | Workload data |
| Services at risk | VMSS fleet |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

