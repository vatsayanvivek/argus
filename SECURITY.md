# Security Policy

## Reporting a vulnerability

ARGUS is a security tool — vulnerability reports are taken seriously
and triaged within 48 hours.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report privately via **GitHub Security Advisories**: go to
the repository's Security tab and click "Report a vulnerability". This
creates a private advisory only the maintainer can see.

Include:

- A description of the vulnerability
- Steps to reproduce
- The version of ARGUS affected (`argus --version`)
- Your suggested fix (optional)
- A safe contact channel for follow-up

For coordinated disclosure with formal CVE assignment, mention "CVE
coordination requested" in the advisory title.

## Disclosure timeline

- **Day 0:** Vulnerability reported privately.
- **Day 2:** Maintainer acknowledges receipt.
- **Day 14:** Fix developed and tested.
- **Day 21:** New release published.
- **Day 30:** Public advisory and CVE issued (if applicable).

## Scope

In scope:
- Bugs that cause ARGUS to miss real findings (false negatives)
- Bugs that cause ARGUS to invent findings (false positives)
- Crashes, panics, or denial-of-service in the scanner
- Authentication or token-handling issues
- Unsafe file operations on the local machine
- Embedded credentials in any release artifact

Out of scope:
- Findings against your own Azure environment that you disagree with
  (open a regular issue)
- Suggestions for new Rego rules (open a regular issue)
- Reports against modified or forked versions (the license forbids
  modification — see [LICENSE](LICENSE))

## Supported versions

Only the latest released version receives security fixes. Older
versions are unsupported.
