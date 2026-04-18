# zt_ai_001 — Azure OpenAI / Cognitive Services account is exposed to the public internet

!!! note "Summary"
    **Severity:** :material-alert: High · **Pillar:** Workload · **Chain role:** ANCHOR

## Description

Cognitive Services accounts (including Azure OpenAI deployments) configured with public network access accept inference requests from any source IP. Attackers who obtain (or guess) the subscription key can submit prompts, poison embeddings, or exfiltrate training data from any location — there is no network boundary to contain the blast radius.

## Mapping

| Framework | Control / Reference |
|---|---|
| NIST 800-53 | AC-4, SC-7 |
| NIST 800-207 | Tenet 5 - All resource authentication and authorization are dynamic and strictly enforced before access is allowed |
| CIS Azure | — |
| MITRE ATT&CK Technique | T1078.004 |
| MITRE ATT&CK Tactic | Persistence |
| Zero-Trust Tenet | Tenet 5 |
| Framework tags | nist-800-207, argus-zt |

## Source

Rule defined at `policies/azure/zt/ai/zt_ai_001.rego`.

[:material-github: View on GitHub](https://github.com/vatsayanvivek/argus/blob/main/policies/azure/zt/ai/zt_ai_001.rego){ .md-button }
