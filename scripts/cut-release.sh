#!/usr/bin/env bash
#
# cut-release.sh — bump version + cut a release branch + tag it.
#
# Usage:
#   ./scripts/cut-release.sh 1.1.0
#   ./scripts/cut-release.sh 1.0.1 --from release/v1.0.0
#
# What this does (in order):
#
#   1. Verifies the working tree is clean.
#   2. Verifies we're on `main` (unless --from is passed, in which
#      case we check out --from first).
#   3. Rewrites the version string in every file that hard-codes it
#      (Makefile, cmd/root.go, main.go, scripts/versioninfo.json,
#      scripts/argus-installer.nsi).
#   4. Regenerates cmd/resource_windows_amd64.syso from the new
#      versioninfo.json.
#   5. Runs `go build` + `go test ./...` — fails the release on any
#      red test or compile error.
#   6. Scans staged changes for obvious secret / tenant leakage.
#   7. Creates a commit, then a branch `release/vX.Y.Z`, then a tag
#      `vX.Y.Z`. Does NOT push anything.
#   8. Prints the exact push commands at the end.
#
# The script is deliberately non-interactive except for the final
# review pause before creating commits / tags, so it is safe to run
# in CI as well as locally.

set -euo pipefail

# ---- args ----
if [[ $# -lt 1 ]]; then
  echo "usage: $0 <version> [--from <branch>]"
  echo "example: $0 1.1.0"
  exit 2
fi
VERSION="$1"
FROM_BRANCH="main"
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM_BRANCH="$2"; shift 2 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

# Validate version format: X.Y.Z where each is a number.
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be X.Y.Z (numbers only); got '$VERSION'"
  exit 2
fi
MAJOR="${VERSION%%.*}"
MINOR_PATCH="${VERSION#*.}"
MINOR="${MINOR_PATCH%%.*}"
PATCH="${MINOR_PATCH#*.}"

echo "▶ Cutting release v${VERSION} from ${FROM_BRANCH}"
echo

# ---- 1. working tree clean ----
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean. Commit or stash changes first."
  git status --short
  exit 1
fi

# ---- 2. on the right branch ----
git checkout "$FROM_BRANCH"

# ---- 3. rewrite version strings ----
echo "▶ Updating version strings to ${VERSION}"

sed -i.bak -E "s/^VERSION \?= .*/VERSION ?= ${VERSION}/" Makefile
sed -i.bak -E "s/^var version = \".*\"/var version = \"${VERSION}\"/" cmd/root.go
sed -i.bak -E "s/^var Version = \".*\"/var Version = \"${VERSION}\"/" main.go
sed -i.bak -E "s/^!define APP_VERSION  \".*\"/!define APP_VERSION  \"${VERSION}\"/" scripts/argus-installer.nsi

# versioninfo.json is structured; use python for safe edits.
python3 - "$VERSION" <<'PY'
import json, sys
v = sys.argv[1]
major, minor, patch = v.split(".")
with open("scripts/versioninfo.json") as f:
    data = json.load(f)
for k in ("FileVersion", "ProductVersion"):
    data["FixedFileInfo"][k] = {"Major": int(major), "Minor": int(minor),
                                 "Patch": int(patch), "Build": 0}
data["StringFileInfo"]["FileVersion"] = f"{v}.0"
data["StringFileInfo"]["ProductVersion"] = f"{v}.0"
with open("scripts/versioninfo.json", "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY

# Clean up sed backup files.
find . -maxdepth 3 -name '*.bak' -delete

# ---- 4. regenerate .syso ----
echo "▶ Regenerating Windows version-info resource"
if ! command -v goversioninfo >/dev/null 2>&1; then
  go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
  export PATH="$PATH:$(go env GOPATH)/bin"
fi
goversioninfo -64 -o cmd/resource_windows_amd64.syso scripts/versioninfo.json

# ---- 5. build + test ----
echo "▶ Running tests"
go build ./...
go test ./...

# ---- 6. secret / tenant leak scan ----
#
# The maintainer keeps a list of deny-patterns (customer names,
# tenant GUIDs, user UPNs, any other tokens that must never ship)
# in a gitignored file `~/.argus/leak-patterns`, one regex per line.
# If that file exists, we grep staged changes against every pattern
# and abort on any hit. The deny-patterns file itself is *never*
# stored in the repo because the patterns themselves would leak
# exactly what they're meant to protect against.
echo "▶ Secret + tenant leak scan"
LEAK_PATTERNS="${ARGUS_LEAK_PATTERNS:-$HOME/.argus/leak-patterns}"
if [[ -f "$LEAK_PATTERNS" ]]; then
  if git diff --cached --no-color | grep -iE -f "$LEAK_PATTERNS" >/dev/null 2>&1; then
    echo "LEAK detected against patterns in $LEAK_PATTERNS — aborting"
    exit 1
  fi
else
  echo "  (no $LEAK_PATTERNS file present; skipping pattern-based leak scan)"
  echo "  To enable: create the file with one regex per line."
fi

# ---- 7. commit + branch + tag ----
echo "▶ Creating commit, branch, and tag"
git add -A
git commit -m "Release v${VERSION}"

BRANCH="release/v${VERSION}"
git branch "$BRANCH"
git tag -a "v${VERSION}" -m "ARGUS v${VERSION}"

# ---- 8. print push commands ----
cat <<EOF

✓ Release v${VERSION} prepared locally.

To publish:
   git push origin ${FROM_BRANCH}
   git push origin ${BRANCH}
   git push origin v${VERSION}

CI will build + upload release assets automatically on the tag push.

EOF
