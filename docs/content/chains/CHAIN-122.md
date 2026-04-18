# CHAIN-122 — AKS node pool SSH enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

AKS node pool VMs have SSH enabled and accept password auth. SSH is meant for on-call debugging; the node has full kubelet credentials and can impersonate the cluster to the control plane.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_006`](../rules/zt_wl_006.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Brute-force SSH against node public IP or peered subnet.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1110`  
**Enabled by:** [`zt_wl_006`](../rules/zt_wl_006.md)  

**Attacker gain:** Node shell.


### Step 2 — Read /etc/kubernetes/kubelet.conf; impersonate kubelet.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Cluster-wide pod create/delete.


## Blast radius

| | |
|---|---|
| Initial access | SSH to node. |
| Max privilege | Cluster admin via kubelet. |
| Data at risk | Every pod secret |
| Services at risk | Entire AKS cluster |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

