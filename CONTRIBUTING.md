# Contributing to ARGUS

**ARGUS is source-available, not open source.** Contributions are not accepted.

## Why?

ARGUS is published under the [PolyForm Strict License 1.0.0](LICENSE),
which permits reading, auditing, and running the software but does not
permit modification, forking, or redistribution. This is a deliberate
choice to keep the rule library, attack-chain definitions, and report
schema consistent across every deployment.

## What you CAN do

- ✅ Run `argus` against your own Azure environment
- ✅ Read every line of source code to audit it
- ✅ File a bug report if `argus` crashes or returns wrong data
- ✅ Suggest a new rule or attack chain via a feature request
- ✅ Use the generated reports in your own compliance documentation
- ✅ Reference ARGUS in academic papers and conference talks

## What you CANNOT do

- ❌ Fork and publish your own modified version
- ❌ Submit a Pull Request (the repo does not accept PRs)
- ❌ Embed or vendor the source code into another project
- ❌ Re-release the binary under a different name
- ❌ Sell ARGUS or charge for access to a hosted version

## How to report bugs

Open a [GitHub Issue](https://github.com/vatsayanvivek/argus/issues)
with:

1. Your `argus --version` output
2. The exact command you ran (with credentials redacted)
3. The error message or unexpected behavior
4. The platform: macOS / Linux / Windows + version

## How to request features

Open a [GitHub Issue](https://github.com/vatsayanvivek/argus/issues)
labelled `feature-request` describing:

1. What you want ARGUS to detect or do
2. Why existing rules don't cover it
3. Any reference materials (CIS Azure, NIST, MITRE ATT&CK ID)

The maintainer will triage requests and may implement them in a future
release. There is no SLA on community feature requests.
