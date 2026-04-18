# CHAIN-035 — Cognitive Services API Abuse to Data Exfil

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Cognitive Services (including Azure OpenAI, Speech, Vision, and Language endpoints) are configured with public network access enabled and API keys that are not rotated or restricted. No Azure Firewall or network virtual appliance inspects outbound traffic, and no centralized Log Analytics workspace aggregates diagnostic telemetry. An attacker who obtains an API key - from a committed config file, a client-side application, or a compromised developer workstation - can call the Cognitive Services endpoints from any IP worldwide. They abuse the AI/ML APIs to process, extract, and exfiltrate sensitive data: running OCR on confidential documents, using Language Understanding to extract PII from text corpora, or using Azure OpenAI to summarize and exfiltrate proprietary content. No network control intercepts the traffic, and no logging captures the anomalous usage pattern.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_020`](../rules/zt_data_020.md) | Trigger |
| [`zt_net_011`](../rules/zt_net_011.md) | Trigger |
| [`zt_vis_011`](../rules/zt_vis_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain a Cognitive Services API key from exposed source code, client-side JavaScript, or a compromised developer machine.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_020`](../rules/zt_data_020.md)  

> GitHub dorking for 'cognitiveservices.azure.com' + key patterns; client-side SPAs that embed the key directly; environment variables on a compromised build agent.

**Attacker gain:** Valid API key for one or more Cognitive Services endpoints.


### Step 2 — Call the Cognitive Services REST API from an external network to validate the key and enumerate available models and deployments.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1526`  
**Enabled by:** [`zt_data_020`](../rules/zt_data_020.md)  

> GET https://{account}.cognitiveservices.azure.com/openai/deployments?api-version=2023-05-15 with Ocp-Apim-Subscription-Key header; public network access allows the call from any IP.

**Attacker gain:** Confirmed working key and a list of deployed models, endpoints, and available capabilities.


### Step 3 — Abuse the AI endpoints to process sensitive data: run OCR on uploaded documents, extract entities from text, or use chat completions to summarize proprietary content.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_net_011`](../rules/zt_net_011.md)  

> POST /openai/deployments/{model}/chat/completions with attacker-supplied prompts referencing injected context; POST /vision/v3.2/ocr with uploaded images containing confidential documents.

**Attacker gain:** AI-processed output containing extracted PII, summarized IP, or OCR text from confidential documents.


### Step 4 — Exfiltrate processed data over HTTPS to attacker infrastructure, blending with normal API response traffic.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1041`  
**Enabled by:** [`zt_net_011`](../rules/zt_net_011.md)  

> All Cognitive Services responses return over HTTPS on port 443; no Azure Firewall or NVA inspects or restricts the traffic pattern. Exfil volume is masked by the API's own response payloads.

**Attacker gain:** Extracted and structured sensitive data on attacker-controlled infrastructure.


### Step 5 — Continue abuse undetected because no centralized logging captures Cognitive Services diagnostic events.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_011`](../rules/zt_vis_011.md)  

> Cognitive Services diagnostic settings are not configured to send to a Log Analytics workspace; no alert rule monitors abnormal request volumes, geographic anomalies, or unusual model usage patterns.

**Attacker gain:** Sustained API abuse with no detection or cost anomaly alert reaching the operations team.


## Blast radius

| | |
|---|---|
| Initial access | Leaked Cognitive Services API key usable from any public IP. |
| Lateral movement | API key → Cognitive Services endpoints → AI-assisted data extraction and processing. |
| Max privilege | Full data-plane access to all Cognitive Services resources sharing the compromised key. |
| Data at risk | Documents processed by OCR/Vision, Text processed by Language services, Prompts and completions from OpenAI endpoints, Training data and fine-tuned models |
| Services at risk | Azure Cognitive Services, Azure OpenAI, Computer Vision, Language Understanding, Speech Services |
| Estimated scope | All Cognitive Services resources accessible by the compromised key |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

