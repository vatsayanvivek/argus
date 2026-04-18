# CHAIN-138 — VM Monitor agent missing — no host forensics

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Production VMs don't have Azure Monitor Agent installed. During IR, the SOC has neither process execution logs nor file-integrity events. Forensics depends entirely on host-level artifacts captured post-incident.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_008`](../rules/zt_wl_008.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise VM; actions leave no host-level telemetry streamed out.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_wl_008`](../rules/zt_wl_008.md)  

**Attacker gain:** Silent compromise.


### Step 2 — Cannot reconstruct attacker actions after the fact.

**Actor:** SOC  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Forensic blindness.


## Blast radius

| | |
|---|---|
| Initial access | VM compromise. |
| Max privilege | Forensic blindness. |
| Data at risk | IR integrity |
| Services at risk | All VM-based workloads |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

