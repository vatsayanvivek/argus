# CHAIN-116 — Bastion hairpin into peer subnet

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Azure Bastion is deployed in a hub VNet that peers to many spoke VNets. Any authenticated Bastion user can SSH into any VM in any peered subnet. No subnet-level scoping applied — so a developer with read RBAC can reach prod VMs through Bastion.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_014`](../rules/zt_net_014.md) | Trigger |
| [`zt_net_003`](../rules/zt_net_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Open Bastion; connect to a VM in a prod subnet they shouldn't.

**Actor:** Legit user  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_014`](../rules/zt_net_014.md)  

**Attacker gain:** Prod shell access.


### Step 2 — Pivot to further prod systems via Bastion.

**Actor:** Attacker with user creds  
**MITRE ATT&CK:** `T1021.004`  
**Enabled by:** [`zt_net_003`](../rules/zt_net_003.md)  

**Attacker gain:** Prod lateral movement.


## Blast radius

| | |
|---|---|
| Initial access | Bastion user login. |
| Max privilege | All peered VMs. |
| Data at risk | Any VM reachable via hub Bastion |
| Services at risk | Hub-and-spoke topology |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

