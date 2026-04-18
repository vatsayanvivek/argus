# CHAIN-135 — Windows VM with Legacy Auth / NTLM enabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Windows VM accepts NTLM authentication and exposes SMB (445) to the VNet. An attacker who compromises a low-privilege VM can SMB-relay against the target, capturing a domain-hashed credential for offline crack.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_023`](../rules/zt_wl_023.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Run ntlmrelayx against target VM.

**Actor:** Attacker on low-priv VM  
**MITRE ATT&CK:** `T1557.001`  
**Enabled by:** [`zt_wl_023`](../rules/zt_wl_023.md)  

**Attacker gain:** NTLM auth response captured.


### Step 2 — Crack offline; pass the hash.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1550.002`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Domain cred or admin access.


## Blast radius

| | |
|---|---|
| Initial access | Low-priv VM + target VM. |
| Max privilege | Domain credentials. |
| Data at risk | Domain-wide AD-joined systems |
| Services at risk | Windows domain |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

