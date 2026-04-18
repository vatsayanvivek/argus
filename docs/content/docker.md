# Docker

ARGUS ships as a hardened multi-arch image based on [Chainguard `static`][chainguard] —
distroless, minimal CVE surface, runs as non-root, signed + attested.

[chainguard]: https://www.chainguard.dev/chainguard-images

## Pull

```bash
docker pull ghcr.io/vatsayanvivek/argus:latest
```

Or pin to a specific version:

```bash
docker pull ghcr.io/vatsayanvivek/argus:v1.1.1
```

## Run a scan

=== "Bash / zsh"

    ```bash
    docker run --rm \
      -v ~/.azure:/home/nonroot/.azure:ro \
      -v "$(pwd)/argus-output":/out \
      ghcr.io/vatsayanvivek/argus:latest \
      scan --out /out
    ```

=== "PowerShell"

    ```powershell
    docker run --rm `
      -v ${HOME}/.azure:/home/nonroot/.azure:ro `
      -v "${PWD}/argus-output:/out" `
      ghcr.io/vatsayanvivek/argus:latest `
      scan --out /out
    ```

=== "Windows CMD"

    ```cmd
    docker run --rm ^
      -v %USERPROFILE%/.azure:/home/nonroot/.azure:ro ^
      -v %cd%/argus-output:/out ^
      ghcr.io/vatsayanvivek/argus:latest ^
      scan --out /out
    ```

## Service principal

```bash
docker run --rm \
  -e AZURE_CLIENT_ID=$AZURE_CLIENT_ID \
  -e AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET \
  -e AZURE_TENANT_ID=$AZURE_TENANT_ID \
  -v "$(pwd)/argus-output":/out \
  ghcr.io/vatsayanvivek/argus:latest \
  scan --out /out
```

## IaC-only scan (no Azure credentials required)

```bash
docker run --rm \
  -v "$(pwd)":/iac:ro \
  -v "$(pwd)/argus-output":/out \
  ghcr.io/vatsayanvivek/argus:latest \
  scan --iac-only --iac-path /iac --out /out
```

## Verify the image

Every image is signed with [cosign][cosign] via GitHub OIDC, attested with SLSA build
provenance, and shipped with a Syft-generated SPDX SBOM.

```bash
# Verify the signature
cosign verify ghcr.io/vatsayanvivek/argus:latest \
  --certificate-identity-regexp "https://github.com/vatsayanvivek/argus/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Download the SBOM
cosign download sbom ghcr.io/vatsayanvivek/argus:latest > argus-sbom.spdx.json

# Download attestations
cosign download attestation ghcr.io/vatsayanvivek/argus:latest
```

[cosign]: https://docs.sigstore.dev/cosign/overview/

## Multi-arch

Images are published for `linux/amd64` and `linux/arm64` via native runners
(no QEMU emulation). Docker picks the right one automatically.

## What's NOT in the image

By design. Chainguard `static` is the base, which contains:

- :material-check: ARGUS binary
- :material-check: CA certificates
- :material-check: `/etc/passwd` entry for `nonroot` (uid 65532)

And nothing else. No shell. No package manager. No writable filesystem outside `/tmp`.
If you need to debug, use `docker run --entrypoint /argus ... --help` or inspect
locally — you cannot `docker exec` into a shell because there isn't one.

This is deliberate. Attackers who compromise the container have no tools to pivot with.

## Image size

Roughly 20–25 MB (platform-dependent). That's the entire ARGUS binary +
the minimal Chainguard base. For comparison, most Python-based scanners ship at 300 MB+.
