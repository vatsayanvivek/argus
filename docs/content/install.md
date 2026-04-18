# Install ARGUS

ARGUS is a single static binary. Pick your platform — installation is one command.

## Windows

=== "Installer (recommended)"

    ```powershell
    # Download the NSIS installer
    iwr https://github.com/vatsayanvivek/argus/releases/latest/download/argus-installer.exe -OutFile argus-installer.exe
    # Run it (adds argus to PATH)
    .\argus-installer.exe
    ```

=== "Portable EXE"

    ```powershell
    iwr https://github.com/vatsayanvivek/argus/releases/latest/download/argus-windows-amd64.exe -OutFile argus.exe
    .\argus.exe install
    ```

!!! warning "Windows SmartScreen"
    On unsigned binaries, SmartScreen shows "Unknown publisher" and asks you to click
    "More info → Run anyway." This is expected until code-signing is in place —
    see [Trust & verification](trust.md) for how to verify the binary instead.

## macOS

=== "Apple Silicon (M1 / M2 / M3)"

    ```bash
    curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-darwin-arm64 -o argus
    chmod +x argus
    ./argus install
    ```

=== "Intel"

    ```bash
    curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-darwin-amd64 -o argus
    chmod +x argus
    ./argus install
    ```

!!! tip "macOS Gatekeeper"
    First run may be blocked. Right-click → Open, then accept the prompt. Binaries
    will be notarised in a future release.

## Linux

=== "amd64"

    ```bash
    curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-amd64 -o argus
    chmod +x argus
    sudo ./argus install
    ```

=== "arm64"

    ```bash
    curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-arm64 -o argus
    chmod +x argus
    sudo ./argus install
    ```

## Docker

```bash
# Pull the hardened Chainguard-based image
docker pull ghcr.io/vatsayanvivek/argus:latest

# Run with your Azure credentials + output mounted to your host
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

## From source

Requires Go 1.25+.

```bash
git clone https://github.com/vatsayanvivek/argus.git
cd argus
make build
./argus --version
```

## Verify the download

Every release ships with:

- **SHA-256 checksums** — `SHA256SUMS`
- **Cosign signature** — `SHA256SUMS.sig`, `SHA256SUMS.pem`
- **SLSA build provenance** — attached to release artifacts
- **SPDX SBOM** — `argus-v*-sbom.spdx.json`

See [Trust & verification](trust.md) for the exact `cosign verify-blob` commands.

## Next steps

1. [Run your first scan](quickstart.md)
2. [Wire into CI / CD](cicd.md)
3. [Browse the rule catalog](rules/index.md)
