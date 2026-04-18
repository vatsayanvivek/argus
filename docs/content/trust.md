# Trust & verification

ARGUS ships with a complete supply-chain transparency stack. You don't have to trust us —
you can verify every artifact independently.

## What's published for every release

| Artifact | Purpose | Where |
|---|---|---|
| **Binaries** (5 platforms) | The scanner itself | Release page |
| **`SHA256SUMS`** | SHA-256 of every binary | Release page |
| **`SHA256SUMS.sig` + `.pem`** | Cosign signature + cert of SHA256SUMS | Release page |
| **SPDX SBOM** | Full dependency tree | Release page + GHCR image |
| **SLSA build provenance** | Proves the binary was built by our CI | GitHub attestations |
| **Trivy CVE report** | CVE scan of binaries + image | GitHub code scanning |
| **Cosign signed image** | GHCR container image | `ghcr.io/vatsayanvivek/argus` |

## Verify a binary

### 1. SHA-256 match

```bash
# Download the binary and the sums file
curl -L -o argus-linux-amd64 https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-amd64
curl -L -o SHA256SUMS       https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS

# Verify
sha256sum -c SHA256SUMS --ignore-missing
# argus-linux-amd64: OK
```

### 2. Cosign-verify the SHA256SUMS file

```bash
# Download signature + certificate
curl -L -o SHA256SUMS.sig https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS.sig
curl -L -o SHA256SUMS.pem https://github.com/vatsayanvivek/argus/releases/latest/download/SHA256SUMS.pem

# Verify the signature was made by our GitHub Actions workflow
cosign verify-blob \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.pem \
  --certificate-identity-regexp "https://github.com/vatsayanvivek/argus/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
# Verified OK
```

If that returns `Verified OK`, the file was signed by **our** release workflow —
impossible to forge without compromising either GitHub's OIDC or Sigstore.

## Verify the Docker image

```bash
# Verify signature (keyless — GitHub OIDC identity)
cosign verify ghcr.io/vatsayanvivek/argus:latest \
  --certificate-identity-regexp "https://github.com/vatsayanvivek/argus/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Inspect the attestations
cosign download attestation ghcr.io/vatsayanvivek/argus:latest | jq

# Pull the SBOM
cosign download sbom ghcr.io/vatsayanvivek/argus:latest > argus-sbom.spdx.json
```

## Verify SLSA build provenance

Every release is attested via [`actions/attest-build-provenance`][slsa]. This is a
GitHub-native SLSA L3 attestation that binds:

- The binary's SHA-256
- The exact commit SHA that built it
- The exact workflow run ID
- The builder's identity (GitHub Actions runner)

```bash
# Install gh + gh-attestation
gh extension install github/gh-attestation

# Verify
gh attestation verify argus-linux-amd64 \
  --owner vatsayanvivek \
  --repo argus
```

[slsa]: https://github.com/actions/attest-build-provenance

## Where to find each link

| What | URL |
|---|---|
| Latest release | [github.com/vatsayanvivek/argus/releases/latest](https://github.com/vatsayanvivek/argus/releases/latest) |
| GHCR image | `ghcr.io/vatsayanvivek/argus` |
| SLSA attestations | [Attestations tab on each release](https://github.com/vatsayanvivek/argus/attestations) |
| Trivy SARIF | [GitHub code scanning](https://github.com/vatsayanvivek/argus/security/code-scanning) |
| SBOM | Attached to each release + embedded in image |
| Source code | [github.com/vatsayanvivek/argus](https://github.com/vatsayanvivek/argus) |

## What to do if verification fails

Don't run the binary. Report it via [SECURITY.md](https://github.com/vatsayanvivek/argus/blob/main/SECURITY.md).

Verification failure means one of:

1. The download was corrupted in transit (retry).
2. Your local `cosign` or `sha256sum` is broken (check the tool).
3. The signing key / identity has changed (check release notes).
4. The artifact was tampered with in the supply chain (report to us immediately).

We publish verification commands for every release and test them ourselves before
shipping. If you hit a problem, it's almost always #1 or #2 — but we take #4 seriously.
