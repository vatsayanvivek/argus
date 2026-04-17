# Building trust for the ARGUS binary — post-release checklist

ARGUS is an unsigned open-source security tool. Without code-signing
certs (PolyForm Strict isn't OSI-approved, so the free SignPath
program doesn't apply), we can't make the SmartScreen / Defender
"protected your PC" warning disappear on day one of a fresh release.

What we **can** do, for free, is build reputation signals that every
modern endpoint security product weights highly. Do these after every
major release. They take ~15 minutes end-to-end and materially shorten
the time before Windows stops flagging the binary.

## Checklist (run after every `git push --tags`)

### 1. Submit Windows binaries to Microsoft for reputation

Microsoft operates a public submission portal that feeds directly
into SmartScreen + Microsoft Defender for Endpoint reputation.
Takes 1–3 business days for a response. Submitting builds
reputation per-publisher and per-file-hash.

- **URL**: https://www.microsoft.com/en-us/wdsi/filesubmission
- **Who**: use a Microsoft account (personal or org)
- **Category**: select **"Developer"**
- **What to submit**: upload each Windows asset from the release:
  - `argus-windows-amd64.exe`
  - `argus-setup.exe` (the NSIS installer)
- **Details block** — paste this verbatim so reviewers have
  immediate context:

  ```
  ARGUS is an open-source Microsoft Azure security posture scanner. It
  reads Azure Resource Graph + Microsoft Graph APIs to identify
  misconfigurations and attack chains; it does not modify any Azure
  resources. The binary is unsigned because the project uses a source-
  available (PolyForm Strict) license that the free open-source code-
  signing programs (SignPath, Certum OSS) do not cover.

  This submission is to request reputation seeding so Windows
  Defender SmartScreen does not flag the installer on legitimate
  downloads.

  Source: https://github.com/vatsayanvivek/argus
  Build provenance: attested via GitHub Actions SLSA
  SBOM: attached to every release as *.sbom.spdx.json
  ```

- **Response**: Microsoft emails the submission result (typically
  "Not malware"). After 2–3 releases with consistent clean
  submissions, reputation stabilises and SmartScreen stops warning.

### 2. Submit to VirusTotal

VirusTotal scans uploaded files against 70+ AV engines and publishes
the result publicly. Clean scans build AV-vendor reputation
cross-industry.

- **URL**: https://www.virustotal.com/gui/home/upload
- **Who**: optional account (anonymous uploads also work; account
  lets you claim the submission)
- **What to submit**: same files as the Microsoft submission, plus
  optionally the macOS and Linux binaries — multi-platform clean
  scans help register ARGUS as a "known good" family.
- **Post-submission**: star the submission so the public permalink
  ranks higher in reputation lookups. Paste the VirusTotal URL into
  the release notes (`gh release edit`) so users can self-verify.

### 3. Verify the SLSA attestation on Sigstore Rekor

GitHub's `actions/attest-build-provenance` publishes a signed
attestation to the Sigstore public transparency log (Rekor). After
the release workflow completes:

- Check: https://search.sigstore.dev/?logIndex= ... use the
  `attestation-id` printed in the workflow summary
- Confirm the attestation shows up and references our repo + tag
- The presence of a public, searchable, cryptographically-signed
  build attestation is a reputation signal on its own

### 4. Validate SBOM consumption

Ensure the SBOMs we attached to the release parse cleanly in
common supply-chain tooling:

```bash
# Grype (free, Anchore)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /tmp
/tmp/grype sbom:./dist/argus-linux-amd64.sbom.spdx.json

# Dependency Track (self-hosted; only if deployed)
curl -X POST https://<dep-track-url>/api/v1/bom \
  -H "X-API-Key: <key>" \
  -F "autoCreate=true" \
  -F "projectName=argus" \
  -F "projectVersion=1.9.0" \
  -F "bom=@dist/argus-linux-amd64.sbom.spdx.json"
```

Any parse error means the SBOM generation step in CI produced bad
output — fix the workflow, re-release.

### 5. (Optional, paid) Apply for code signing later

If the license constraint on SignPath is ever relaxed (e.g. the
project relicenses to Apache 2.0), apply at https://signpath.org.
Until then, the reputation stack above — SmartScreen submission +
VirusTotal + SLSA + SBOM + Docker image alternative — is the
realistic substitute.

## Timeline expectations

| Release | SmartScreen behaviour |
|---|---|
| v1.x.0 (first submission) | Full "Windows protected your PC" warning. Users must click More info → Run anyway |
| v1.x.1 after MS review | Warning may downgrade to a simpler prompt |
| v1.(x+1).y after several releases | Warning typically disappears for the named publisher+binary |

The Docker image path (ghcr.io/vatsayanvivek/argus) sidesteps this
entirely — users who can't or won't accept the first-time
SmartScreen prompt have a fully-signed, scanned, attested alternative
via `docker pull`.
