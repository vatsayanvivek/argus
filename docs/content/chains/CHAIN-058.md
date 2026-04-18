# CHAIN-058 — Service principal with privileged Graph role + no cred rotation

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A service principal holds a dangerous Microsoft Graph application permission (Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All) and its client secret never expires. Any exposure of that secret — CI log leak, GitHub push, developer laptop exfil — is a permanent tenant backdoor.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Grep GitHub / Postman / CI logs for the client secret.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Valid SP credential.


### Step 2 — Mint a Graph token and call directoryRoles to grant itself Global Admin.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** Global Admin via application permission.


## Blast radius

| | |
|---|---|
| Initial access | Any secret leak. |
| Max privilege | Global Admin via self-promotion. |
| Data at risk | Directory, All app secrets, All mailboxes |
| Services at risk | Entra ID, Graph, All M365 |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

