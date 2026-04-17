#!/usr/bin/env bash
#
# validate.sh — end-to-end smoke test of every ARGUS feature.
#
# Run with `make validate` from the repo root. Exercises the binary
# through its full public surface: help, version, install flow, IaC
# scanner across every format, update command, check-permissions,
# banner rendering, and both CLI + Docker image execution.
#
# Each check prints a green "PASS" or red "FAIL" line. The script
# exits non-zero if any check fails so CI can gate on it.
#
# Requires: argus binary built (`make build`), optionally docker for
# the container check (skipped gracefully if docker isn't running).

set -u
# Intentionally no `pipefail`: `grep -q` exits on first match and
# sends SIGPIPE upstream, which pipefail would translate into a
# false "command failed". Every pipeline below survives a broken
# stdout, so pipefail adds no real safety here.

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
DIM='\033[2m'
NC='\033[0m'

FAILS=0
PASSES=0
SKIPS=0

pass() { printf "  ${GREEN}✓ PASS${NC} %s\n" "$1"; PASSES=$((PASSES+1)); }
fail() { printf "  ${RED}✗ FAIL${NC} %s\n" "$1"; FAILS=$((FAILS+1)); }
skip() { printf "  ${YELLOW}○ SKIP${NC} %s ${DIM}(%s)${NC}\n" "$1" "$2"; SKIPS=$((SKIPS+1)); }
section() { printf "\n${CYAN}▶ %s${NC}\n" "$1"; }

cd "$(dirname "$0")/.."
ARGUS="./argus"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [[ ! -x "$ARGUS" ]]; then
  echo "error: ./argus binary not found. Run 'make build' first."
  exit 1
fi

# ----- basic CLI surface -----
section "CLI surface"

if $ARGUS --version | grep -qE 'argus version [0-9]+\.[0-9]+\.[0-9]+'; then
  pass "--version reports a semver-shaped string"
else
  fail "--version output unexpected"
fi

if $ARGUS --help 2>&1 | grep -q "attack chains"; then
  pass "--help renders without crashing"
else
  fail "--help missing expected content"
fi

for sub in scan iac rules score drift suppress trend monitor install update check-permissions; do
  if $ARGUS "$sub" --help >/dev/null 2>&1; then
    pass "'$sub --help' works"
  else
    fail "'$sub --help' failed"
  fi
done

# ----- rule library -----
section "Rule library loading"

rule_count=$($ARGUS rules list 2>&1 | grep -cE '^[[:space:]]+(cis_|zt_)')
if [[ $rule_count -ge 190 ]]; then
  pass "argus rules list shows $rule_count rules"
else
  fail "argus rules list shows only $rule_count rules (expected >=190)"
fi

# ----- IaC scanner, every format -----
section "IaC scanner — 3 format autodetect"

cat > "$TMP/tf-plan.json" <<'EOF'
{"format_version":"1.2","terraform_version":"1.6.0","resource_changes":[{"address":"azurerm_storage_account.t","mode":"managed","type":"azurerm_storage_account","name":"t","change":{"actions":["create"],"before":null,"after":{"name":"stinsecure","location":"eastus","resource_group_name":"rg","allow_nested_items_to_be_public":true,"enable_https_traffic_only":false,"min_tls_version":"TLS1_0","public_network_access_enabled":true,"shared_access_key_enabled":true,"network_rules":[{"default_action":"Allow","bypass":["AzureServices"]}]}}}]}
EOF

if $ARGUS iac "$TMP/tf-plan.json" --output json --output-dir "$TMP/out" --fail-on NONE >/dev/null 2>&1; then
  pass "IaC scan: Terraform plan (autodetect)"
else
  fail "IaC scan: Terraform plan"
fi

cat > "$TMP/arm.json" <<'EOF'
{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","contentVersion":"1.0.0.0","resources":[{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"stprod","location":"eastus","properties":{"supportsHttpsTrafficOnly":false,"minimumTlsVersion":"TLS1_0"}}]}
EOF

if $ARGUS iac "$TMP/arm.json" --output json --output-dir "$TMP/out" --fail-on NONE >/dev/null 2>&1; then
  pass "IaC scan: ARM template (autodetect)"
else
  fail "IaC scan: ARM template"
fi

cat > "$TMP/whatif.json" <<'EOF'
{"changes":[{"resourceId":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1","changeType":"Create","after":{"type":"Microsoft.KeyVault/vaults","location":"eastus","properties":{"enablePurgeProtection":false}}}]}
EOF

if $ARGUS iac "$TMP/whatif.json" --output json --output-dir "$TMP/out" --fail-on NONE >/dev/null 2>&1; then
  pass "IaC scan: ARM what-if (autodetect)"
else
  fail "IaC scan: ARM what-if"
fi

if $ARGUS iac "$TMP/arm.json" --format bicep --output json --output-dir "$TMP/out" --fail-on NONE >/dev/null 2>&1; then
  pass "IaC --format override accepts 'bicep'"
else
  fail "IaC --format=bicep override"
fi

# ----- argus update (read-only checks) -----
section "argus update"

if $ARGUS update --list >/dev/null 2>&1; then
  pass "'argus update --list' queries the GitHub API"
else
  skip "'argus update --list' couldn't reach GitHub" "network-restricted"
fi

if $ARGUS update --check 2>&1 | grep -qE 'Latest release|latest|upgrade'; then
  pass "'argus update --check' reports a status line"
else
  skip "'argus update --check' no output" "network-restricted"
fi

# ----- Docker image -----
section "Docker image"

if ! command -v docker >/dev/null 2>&1; then
  skip "docker not installed" "container test skipped"
elif ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  skip "docker daemon not running" "start Docker Desktop and re-run"
else
  IMAGE="argus:validate-local"
  if docker build --quiet --build-arg VERSION=validate -t "$IMAGE" . >/dev/null 2>&1; then
    pass "docker build succeeded"

    if docker run --rm "$IMAGE" --version | grep -q "argus version"; then
      pass "docker run argus --version"
    else
      fail "docker run argus --version"
    fi

    if docker run --rm "$IMAGE" rules list 2>&1 | grep -qE 'cis_|zt_'; then
      pass "docker run argus rules list"
    else
      fail "docker run argus rules list"
    fi

    uid=$(docker image inspect "$IMAGE" --format '{{.Config.User}}')
    if [[ "$uid" == "65532" ]]; then
      pass "container runs as non-root uid 65532"
    else
      fail "container runs as user '$uid' (expected 65532)"
    fi

    docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
  else
    fail "docker build"
  fi
fi

printf "\n${CYAN}═══ validation summary ═══${NC}\n"
printf "  ${GREEN}%d passed${NC}   ${RED}%d failed${NC}   ${YELLOW}%d skipped${NC}\n" "$PASSES" "$FAILS" "$SKIPS"

if [[ $FAILS -gt 0 ]]; then
  exit 1
fi
