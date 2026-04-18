# CHAIN-156 — Azure AI Search RAG corpus with PII and unauth read

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An LLM RAG application uses Azure AI Search to retrieve internal documents including customer PII. The search service has public endpoint access and query API keys that are distributed broadly. Anyone with a query key can enumerate the corpus and exfiltrate PII.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_005`](../rules/zt_ai_005.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain a query key from a shared secret store.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_005`](../rules/zt_ai_005.md)  

**Attacker gain:** Query access to index.


### Step 2 — Enumerate documents via wildcard queries; export PII.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Mass PII breach via RAG corpus.


## Blast radius

| | |
|---|---|
| Initial access | Query key distribution. |
| Max privilege | Corpus read. |
| Data at risk | Every document in the index |
| Services at risk | RAG pipeline + downstream LLM usage |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

