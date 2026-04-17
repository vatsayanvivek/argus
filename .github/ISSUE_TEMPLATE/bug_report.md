---
name: Bug report
about: Report unexpected behavior in ARGUS
title: '[BUG] '
labels: bug
assignees: ''
---

## Describe the bug

A clear, concise description of what went wrong.

## To Reproduce

The exact command you ran (with credentials redacted):

```bash
./argus scan --subscription <sub-id> --tenant <tenant-id>
```

## Expected behavior

What you expected ARGUS to do.

## Actual behavior

What ARGUS actually did. Include the error message verbatim.

## Environment

- ARGUS version: `./argus --version`
- OS: macOS / Linux / Windows
- OS version:
- Go version (only if you built from source):
- Azure CLI version: `az --version`
- Auth method: az login / SPN / managed identity

## Scan output

If safe to share, paste the relevant section of the report (with
resource IDs redacted) or attach the JSON output.

## Notes

- ⚠️ ARGUS is source-available. Do not include modified versions of
  the source in bug reports — modifications void the license.
- 🔒 If this bug has security implications, report it via
  [SECURITY.md](../SECURITY.md) instead of a public issue.
