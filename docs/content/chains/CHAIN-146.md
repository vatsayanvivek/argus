# CHAIN-146 — Azure AI Search with public access + admin API key leak

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure AI Search service has public network access and admin API keys that never rotate. A leaked admin key grants full read/write on every index — including ability to drop indexes, add poisoned content, or export entire search corpora.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_005`](../rules/zt_ai_005.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Find admin API key in an app's appsettings.json / GitHub.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_005`](../rules/zt_ai_005.md)  

**Attacker gain:** Admin key for search service.


### Step 2 — Enumerate indexes; export every document.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** RAG corpus exfil + poisoning capability.


## Blast radius

| | |
|---|---|
| Initial access | Leaked admin key. |
| Max privilege | Full search service admin. |
| Data at risk | Every indexed document (RAG corpus) |
| Services at risk | Search service + consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

