# CHAIN-090 — NetApp volume NFSv3 without export policy scoping

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A NetApp volume uses NFSv3 (IP-based auth only) and its export policy allows any subnet in the VNet. A compromised VM in any peered VNet can mount the volume without per-user auth.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_028`](../rules/zt_data_028.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |

## Attack walkthrough

### Step 1 — mount -o nfsvers=3 <netapp>:/vol /mnt.

**Actor:** Attacker on peered VM  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_data_028`](../rules/zt_data_028.md)  

**Attacker gain:** Volume access without per-user auth.


### Step 2 — Read every file, no audit trail of per-user access.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

**Attacker gain:** Silent file exfil.


## Blast radius

| | |
|---|---|
| Initial access | VM foothold in peered VNet. |
| Max privilege | NFS-layer file access. |
| Data at risk | NetApp volume contents |
| Services at risk | NetApp, Dependent file-sharing apps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

