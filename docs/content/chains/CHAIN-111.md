# CHAIN-111 — Private Link DNS misconfig forces fallback to public

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A storage account has Private Link but the private DNS zone is not linked to the consuming VNet. DNS falls back to the public endpoint; traffic now traverses the public internet instead of the private channel. The admin thinks it's private; it isn't.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_022`](../rules/zt_net_022.md) | Trigger |
| [`zt_data_002`](../rules/zt_data_002.md) | Trigger |

## Attack walkthrough

### Step 1 — VNet resolves *.blob.core.windows.net to the public IP.

**Actor:** Misconfig  
**MITRE ATT&CK:** `T1584.002`  
**Enabled by:** [`zt_net_022`](../rules/zt_net_022.md)  

**Attacker gain:** Traffic goes over public Internet.


### Step 2 — Sniff the assumed-private traffic.

**Actor:** External adversary  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_data_002`](../rules/zt_data_002.md)  

**Attacker gain:** Plaintext-on-TLS exfil + MITM potential.


## Blast radius

| | |
|---|---|
| Initial access | Routing-level path exposure. |
| Max privilege | Internet adversary observability. |
| Data at risk | Supposedly private storage traffic |
| Services at risk | Any Private Link consumer with broken DNS |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

