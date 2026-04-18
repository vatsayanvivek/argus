# CHAIN-123 — AKS without network policies — pod-to-pod free-for-all

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

AKS cluster has no NetworkPolicy / Calico enforcement. Any compromised pod can freely reach other pods' services — including kube-system, metrics servers, and the metadata proxy. There is no lateral segmentation inside the cluster.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_009`](../rules/zt_wl_009.md) | Trigger |
| [`zt_wl_012`](../rules/zt_wl_012.md) | Trigger |

## Attack walkthrough

### Step 1 — Scan cluster DNS for service endpoints.

**Actor:** Compromised pod  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_wl_009`](../rules/zt_wl_009.md)  

**Attacker gain:** Full inventory of cluster services.


### Step 2 — Exploit an in-cluster unauthenticated service.

**Actor:** Pod  
**MITRE ATT&CK:** `T1210`  
**Enabled by:** [`zt_wl_012`](../rules/zt_wl_012.md)  

**Attacker gain:** Second pod compromise via cluster-internal reachability.


## Blast radius

| | |
|---|---|
| Initial access | Any pod compromise. |
| Max privilege | Full cluster internal lateral movement. |
| Data at risk | Other pods' secrets and data |
| Services at risk | Every in-cluster service |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

