# CHAIN-117 — VMSS without OS auto-upgrade + public SSH

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A VM Scale Set has OS auto-upgrade disabled and its instance count exposes SSH to the internet. Instances run months-old kernels; any published CVE with public exploit gives one-click RCE on every instance in the pool.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_029`](../rules/zt_wl_029.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Match VMSS banner to known kernel CVE.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1595`  
**Enabled by:** [`zt_wl_029`](../rules/zt_wl_029.md)  

**Attacker gain:** Exploit candidate.


### Step 2 — Exploit kernel CVE; root shell on all instances.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1210`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Fleet-wide compromise.


## Blast radius

| | |
|---|---|
| Initial access | Internet SSH + unpatched kernel. |
| Max privilege | Root on every VMSS instance. |
| Data at risk | Workload data, MI tokens |
| Services at risk | VMSS, Dependent services |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

