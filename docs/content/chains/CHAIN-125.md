# CHAIN-125 — AKS image pulled from untrusted registry

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Pods pull images from public Docker Hub without image signing / admission control. A supply-chain compromise (typosquat, namespace takeover) yields attacker-controlled code in every pod restart.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_014`](../rules/zt_wl_014.md) | Trigger |
| [`zt_wl_013`](../rules/zt_wl_013.md) | Trigger |

## Attack walkthrough

### Step 1 — Publish malicious image to a registry path similar to the real one.

**Actor:** Supply-chain attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

**Attacker gain:** Trojaned image available.


### Step 2 — On pod restart pulls the malicious image; attacker code runs in-cluster.

**Actor:** Kubelet  
**MITRE ATT&CK:** `T1554`  
**Enabled by:** [`zt_wl_013`](../rules/zt_wl_013.md)  

**Attacker gain:** In-cluster code execution.


## Blast radius

| | |
|---|---|
| Initial access | Registry compromise. |
| Max privilege | Pod-level RCE; often cluster-admin via privileged container. |
| Data at risk | Whatever the pod can reach |
| Services at risk | Any workload using the registry |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

