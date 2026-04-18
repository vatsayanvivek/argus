# CHAIN-124 — AKS privileged pod + host path mount

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A pod runs privileged: true AND mounts /var/run/docker.sock or /host. Container escape is trivial — the pod can exec into the host, ptrace other containers, or create new containers with arbitrary parameters.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_010`](../rules/zt_wl_010.md) | Trigger |
| [`zt_wl_013`](../rules/zt_wl_013.md) | Trigger |

## Attack walkthrough

### Step 1 — Access the host socket; docker run --privileged -v /:/host attacker.

**Actor:** Compromised pod  
**MITRE ATT&CK:** `T1611`  
**Enabled by:** [`zt_wl_010`](../rules/zt_wl_010.md)  

**Attacker gain:** Host filesystem access.


### Step 2 — Dump kubelet creds; cluster admin.

**Actor:** Attacker on node  
**MITRE ATT&CK:** `T1552`  
**Enabled by:** [`zt_wl_013`](../rules/zt_wl_013.md)  

**Attacker gain:** Cluster admin from single pod compromise.


## Blast radius

| | |
|---|---|
| Initial access | Any pod compromise. |
| Max privilege | Cluster admin. |
| Data at risk | Every pod's secrets |
| Services at risk | Entire cluster |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

