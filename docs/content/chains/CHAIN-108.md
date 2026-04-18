# CHAIN-108 — Application Gateway with SSL passthrough + backend TLS off

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

App Gateway terminates TLS and sends plain HTTP to backend pools over the VNet. Any VNet-scoped adversary can sniff the internal traffic or inject responses.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_006`](../rules/zt_net_006.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Sniff backend HTTP traffic.

**Actor:** Adversary in VNet  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_net_006`](../rules/zt_net_006.md)  

**Attacker gain:** Session tokens, auth cookies.


### Step 2 — Replay captured session cookies.

**Actor:** Adversary  
**MITRE ATT&CK:** `T1550.004`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

**Attacker gain:** Impersonation of legitimate users.


## Blast radius

| | |
|---|---|
| Initial access | VNet-scoped access. |
| Max privilege | Session hijack. |
| Data at risk | Session + API traffic |
| Services at risk | Apps behind the gateway |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

