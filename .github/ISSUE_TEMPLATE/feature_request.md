---
name: Feature request / new rule
about: Suggest a new ARGUS rule, attack chain, or capability
title: '[FEATURE] '
labels: feature-request
assignees: ''
---

## What should ARGUS detect or do?

A clear description of the new rule, chain, or feature.

## Why isn't this already covered?

Explain why existing rules don't cover this.

## Reference materials

Where is this control defined?

- [ ] CIS Microsoft Azure Foundations Benchmark — section number:
- [ ] NIST 800-53 — control ID:
- [ ] NIST 800-207 — tenet number:
- [ ] MITRE ATT&CK — technique ID:
- [ ] Other:

## Example

If you have a real Azure resource that should trigger this finding,
paste the (redacted) JSON shape so the maintainer can write a Rego
rule against it.

## Notes

- 🚫 ARGUS does not accept Pull Requests. The maintainer will
  implement requested rules in a future release.
- 💼 If you need this urgently, commercial support is available —
  see the README for contact details.
