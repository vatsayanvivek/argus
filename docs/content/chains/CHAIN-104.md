# CHAIN-104 — ExpressRoute without MACsec + carrier compromise

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

ExpressRoute circuit does not enable MAC Layer Security. Traffic between corporate edge and Azure travels clear through the carrier's network. A carrier-level adversary (or compromised physical cross-connect) can sniff or inject.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_023`](../rules/zt_net_023.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Tap the ExpressRoute path at the MMR.

**Actor:** Carrier-level adversary  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_net_023`](../rules/zt_net_023.md)  

**Attacker gain:** Plaintext traffic stream.


### Step 2 — Harvest session tokens; inject forged responses.

**Actor:** Adversary  
**MITRE ATT&CK:** `T1557`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

**Attacker gain:** Full traffic compromise.


## Blast radius

| | |
|---|---|
| Initial access | Carrier-level access. |
| Max privilege | All ExpressRoute traffic. |
| Data at risk | All VNet-to-on-prem traffic |
| Services at risk | Everything traversing this circuit |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

