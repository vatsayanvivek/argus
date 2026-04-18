# Maintainer notes — branching, release, and CI

This file documents the release + branching model for the ARGUS repo.
It is intended for the maintainer's own reference; contributors see
[CONTRIBUTING.md](CONTRIBUTING.md) instead.

## Branching model

ARGUS uses a release-branch model so users who install an older
version can always browse that version's source without wading
through unrelated later changes.

```
main          ──●───●───●──────────●────────●──────  always == latest release
                  ↘             ↘             ↘
release/v1.0.0    ●             │             │     frozen at v1.0.0
release/v1.1.0                  ●             │     frozen at v1.1.0
release/v1.2.0                                ●     frozen at v1.2.0
```

**Rules:**

- `main` is always **the latest released version**. It is not a
  rolling development branch.
- Active work happens on short-lived topic branches (`feature/<name>`
  or `fix/<name>`) that are squash-merged into `main` at release time.
- Every release produces a permanent `release/vX.Y.Z` branch frozen
  at the release commit. These branches are never modified after
  release, except for security backports (see below).
- Every release is tagged on `main` at the release commit; the tag
  name is `vX.Y.Z`.

## Cutting a release

Use the helper script:

```bash
./scripts/cut-release.sh 1.1.0
```

The script:

1. Verifies working tree is clean and on `main`.
2. Bumps version strings in `Makefile`, `cmd/root.go`, `main.go`,
   `scripts/versioninfo.json`, `scripts/argus-installer.nsi`.
3. Regenerates the Windows version-info `.syso` resource.
4. Runs `go build` + `go test ./...`; fails the release on any
   red test or compile error.
5. Runs a pre-push sanity check for tenant / secret leakage.
6. Creates the commit, the `release/vX.Y.Z` branch, and the
   `vX.Y.Z` tag.
7. Prints the exact `git push` commands required. Does **not**
   push on its own.

Push manually once satisfied:

```bash
git push origin main
git push origin release/v1.1.0
git push origin v1.1.0
```

The tag push triggers `.github/workflows/release.yml` which builds
all platform binaries, the Windows installer, the Docker image, and
uploads them to the matching GitHub release with SBOMs and SLSA
attestations attached.

## Security patch on an older release

To patch `release/v1.0.0` after `v1.1.0` has shipped:

```bash
git checkout release/v1.0.0
git checkout -b fix/v1.0.x-cve-XXXXX
# ... apply fix ...
git commit -m "Fix: CVE-XXXXX …"
./scripts/cut-release.sh 1.0.1 --from fix/v1.0.x-cve-XXXXX
```

The script tags `v1.0.1` on the fix branch. `main` stays on the
latest minor and is not affected.

## Non-negotiable rules

- **Never** rewrite history on `main` or any `release/*` branch.
  Those branches are durable references users rely on.
- **Never** merge `main` back into a `release/*` branch. Release
  branches are frozen snapshots.
- **Never** delete a release tag after it has been pushed. Tags
  are load-bearing for `argus update` and for anyone who pinned
  a version.
- **Never** include AI-tool attribution trailers or "Generated with
  ..." footers in commits, PRs, release notes, or any artifact in
  this repo. The maintainer is the sole author of every commit.

## Rule and chain unit tests

Every Rego rule and every attack chain has a dedicated coverage test.
The framework lives in `internal/engine/`:

- `fixtures_test.go` — reusable snapshot builders (NSG shapes, storage
  accounts, service principals, etc.). Add focused builders here when
  a new rule needs a shape we don't have yet — keep rule_coverage_test.go
  free of struct literals.
- `rule_coverage_test.go` — table-driven cases asserting a rule fires
  (or stays silent) for a specific snapshot. **Every new rule should
  land with at least one positive and one negative case.**
- `chain_coverage_test.go` — validates the correlator's trigger-match
  logic (`ALL`, `ANY_TWO`, `ANCHOR_PLUS_ONE`), participation index,
  and severity sort.

Run locally:

```bash
make embed-prep
go test ./internal/engine/... -run 'TestRuleCoverage|TestChain'
```

CI runs these on every push via `.github/workflows/test.yml` (no
separate wiring — it's covered by `go test ./...`). A regression in
rule loading, the Rego→Go input transform, or a rule's own syntax
fails the suite before release.

When adding a new Rego rule:

1. Write the rule in `policies/azure/zt/<category>/`.
2. Re-run `make embed-prep` so the embedded FS picks it up.
3. Add `fires=true` and `fires=false` cases to `rule_coverage_test.go`
   using (or extending) builders in `fixtures_test.go`.
4. If the rule participates in a new attack chain, add the chain to
   the correlator and one `ALL` / `ANCHOR_PLUS_ONE` case to
   `chain_coverage_test.go`.

Field naming reminder: the Rego input is snake_case (see
`engine.TransformSnapshot`). Rules that use camelCase keys
(`passwordCredentials`, `endDateTime`) silently never match against
a real collected snapshot — the coverage tests are the guardrail
against this class of bug.

## CI / release automation

`.github/workflows/release.yml` runs on every tag push matching
`v*` and on `workflow_dispatch` for emergency runs. It:

- Cross-compiles 5 platform binaries (linux/amd64, linux/arm64,
  darwin/amd64, darwin/arm64, windows/amd64)
- Builds the Windows GUI installer (`argus-setup.exe`) via NSIS
- Generates per-binary SBOMs using syft (SPDX JSON)
- Creates a SLSA build-provenance attestation via the
  `actions/attest-build-provenance@v1` GitHub-native action
- Builds + pushes the multi-arch Docker image to `ghcr.io/<owner>/argus`
- Attests the Docker image with its content digest
- Scans the Docker image with Trivy; fails the release on any
  HIGH or CRITICAL CVE in our dependencies
- Signs the Docker image with `cosign` using GitHub OIDC
- Uploads SHA256SUMS, installer, and all binaries + SBOMs to the
  GitHub release

The runner installs `goversioninfo`, NSIS, `syft`, `trivy`, and
`cosign` as part of the job — no manual setup needed.

## Post-release checklist

After the workflow succeeds (typically within 5 minutes of tag push):

1. Verify the GitHub release page shows all expected assets.
2. `docker pull ghcr.io/vatsayanvivek/argus:vX.Y.Z` — confirm it
   runs.
3. Run through the reputation-building steps in
   [scripts/reputation-building.md](scripts/reputation-building.md)
   — submit binaries to Microsoft + VirusTotal for seeding.
4. Announce via whatever channels apply (nothing formal today).
