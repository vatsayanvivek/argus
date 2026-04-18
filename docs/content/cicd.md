# CI / CD integration

ARGUS runs anywhere your CI runner runs. It produces SARIF, JSON, or HTML and exits
non-zero when findings at a configurable severity appear — so it gates broken PRs
without extra plumbing.

## GitHub Actions

```yaml
name: ARGUS security scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  argus:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # needed to upload SARIF
    steps:
      - uses: actions/checkout@v4

      - name: Install ARGUS
        run: |
          curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-amd64 -o argus
          chmod +x argus
          sudo mv argus /usr/local/bin/

      - name: Scan IaC
        run: |
          argus scan \
            --iac-only --iac-path . \
            --format sarif \
            --out ./argus-output \
            --min-severity HIGH

      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: argus-output/argus_*.sarif
```

## GitLab CI

```yaml
argus-scan:
  stage: test
  image: ghcr.io/vatsayanvivek/argus:latest
  script:
    - argus scan --iac-only --iac-path . --format json --out ./argus-output
  artifacts:
    reports:
      sast: argus-output/argus_*.sarif
    paths:
      - argus-output/
```

## Azure DevOps Pipelines

```yaml
- task: Bash@3
  displayName: ARGUS scan
  inputs:
    targetType: inline
    script: |
      curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-amd64 -o argus
      chmod +x argus
      ./argus scan --iac-only --iac-path $(Build.SourcesDirectory) --format sarif --out ./argus-output
- publish: ./argus-output
  artifact: argus-report
```

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('ARGUS scan') {
      steps {
        sh '''
          curl -L https://github.com/vatsayanvivek/argus/releases/latest/download/argus-linux-amd64 -o argus
          chmod +x argus
          ./argus scan --iac-only --iac-path . --format html --out ./argus-output
        '''
        archiveArtifacts artifacts: 'argus-output/**', fingerprint: true
      }
    }
  }
}
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan complete, no findings at or above `--min-severity` |
| `1` | Scan complete, findings present at or above `--min-severity` — PR should be blocked |
| `2` | Scan failed for a reason other than findings (auth, network, invalid flags) |

Configure your CI to fail the pipeline on exit code 1 for the severity threshold you want
to enforce. Default threshold is `HIGH`.

## Airflow / scheduled scans

```yaml
# Run nightly against prod
schedule: "0 2 * * *"
command: |
  argus scan --subscription $PROD_SUB --out /scans/$(date +%F)
```

Pair with S3 / Azure Blob upload and your own drift workflow — or wait for the built-in
`argus watch` continuous mode (Tier B roadmap).
