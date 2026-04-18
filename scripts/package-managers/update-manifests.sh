#!/usr/bin/env bash
# Regenerate package-manager manifests from a released version's SHA256SUMS.
#
# Runs from repo root. Writes:
#   scripts/package-managers/homebrew/argus.rb   (with versions + hashes)
#   scripts/package-managers/scoop/argus.json
#   scripts/package-managers/winget/VatsayanVivek.Argus.*.yaml
#
# Usage:  bash scripts/package-managers/update-manifests.sh 1.2.0
#
# The script pulls SHA256SUMS from the matching GitHub release (no auth
# required) and substitutes hashes into each template in-place. Run this
# after every release; commit the resulting manifest files.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>  (e.g. 1.2.0 — no 'v' prefix)" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sums_url="https://github.com/vatsayanvivek/argus/releases/download/v${VERSION}/SHA256SUMS"
echo "Downloading $sums_url"
curl -fsSL "$sums_url" -o "$tmp/SHA256SUMS"

hash_for() {
  local file="$1"
  awk -v f="$file" '$2 == f || $2 == "*"f { print $1 }' "$tmp/SHA256SUMS"
}

SHA_DARWIN_AMD64="$(hash_for argus-darwin-amd64)"
SHA_DARWIN_ARM64="$(hash_for argus-darwin-arm64)"
SHA_LINUX_AMD64="$(hash_for argus-linux-amd64)"
SHA_LINUX_ARM64="$(hash_for argus-linux-arm64)"
SHA_WINDOWS_AMD64="$(hash_for argus-windows-amd64.exe)"

for v in SHA_DARWIN_AMD64 SHA_DARWIN_ARM64 SHA_LINUX_AMD64 SHA_LINUX_ARM64 SHA_WINDOWS_AMD64; do
  if [[ -z "${!v:-}" ]]; then
    echo "ERROR: could not find SHA for $v in SHA256SUMS" >&2
    exit 1
  fi
done

DATE_ISO="$(date -u +%Y-%m-%d)"

substitute() {
  local src="$1" dst="$2"
  sed \
    -e "s/__VERSION__/${VERSION}/g" \
    -e "s/__RELEASE_DATE__/${DATE_ISO}/g" \
    -e "s/__SHA256_DARWIN_AMD64__/${SHA_DARWIN_AMD64}/g" \
    -e "s/__SHA256_DARWIN_ARM64__/${SHA_DARWIN_ARM64}/g" \
    -e "s/__SHA256_LINUX_AMD64__/${SHA_LINUX_AMD64}/g" \
    -e "s/__SHA256_LINUX_ARM64__/${SHA_LINUX_ARM64}/g" \
    -e "s/__SHA256_WINDOWS_AMD64__/${SHA_WINDOWS_AMD64}/g" \
    "$src" > "$dst"
}

BASE="scripts/package-managers"

substitute "$BASE/homebrew/argus.rb" "$BASE/homebrew/argus.rb.rendered"
substitute "$BASE/scoop/argus.json" "$BASE/scoop/argus.json.rendered"
substitute "$BASE/winget/VatsayanVivek.Argus.installer.yaml" "$BASE/winget/VatsayanVivek.Argus.installer.yaml.rendered"
substitute "$BASE/winget/VatsayanVivek.Argus.locale.en-US.yaml" "$BASE/winget/VatsayanVivek.Argus.locale.en-US.yaml.rendered"
substitute "$BASE/winget/VatsayanVivek.Argus.yaml" "$BASE/winget/VatsayanVivek.Argus.yaml.rendered"

cat <<EOF
Rendered manifests (not yet committed) for ARGUS v${VERSION}:
  $BASE/homebrew/argus.rb.rendered
  $BASE/scoop/argus.json.rendered
  $BASE/winget/VatsayanVivek.Argus.installer.yaml.rendered
  $BASE/winget/VatsayanVivek.Argus.locale.en-US.yaml.rendered
  $BASE/winget/VatsayanVivek.Argus.yaml.rendered

Next steps:
  1. Review the rendered files.
  2. Publish them to:
     - Homebrew:  paste argus.rb.rendered into the vatsayanvivek/homebrew-argus tap
     - Scoop:     paste argus.json.rendered into the scoop bucket
     - Winget:    submit a PR to microsoft/winget-pkgs with the three YAMLs
EOF
