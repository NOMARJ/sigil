# CI/CD Integration Guide

Run Sigil in your CI/CD pipeline to catch malicious code before it reaches production. This guide covers GitHub Actions, GitLab CI, and generic CI systems.

---

## GitHub Actions

Sigil provides a first-party GitHub Action that scans your repository on every push or pull request.

### Basic Setup

Add to `.github/workflows/sigil.yml`:

```yaml
name: Sigil Security Scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: NOMARJ/sigil@main
        with:
          path: .
          threshold: medium
          fail-on-findings: true
```

### Inputs

These match `action.yml` exactly.

| Input              | Default               | Description                                                                                                                 |
| ------------------ | --------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `path`             | `.`                   | Path to scan, relative to the repository root (a single directory or file)                                                  |
| `threshold`        | `medium`              | Minimum verdict level that fails the action: `low`, `medium`, `high`, `critical`                                            |
| `fail-on-findings` | `true`                | Whether to fail the action when the risk score meets the threshold                                                          |
| `phases`           | `all`                 | Comma-separated phase filter: `install-hooks`, `code-patterns`, `network-exfil`, `credentials`, `obfuscation`, `provenance`, `prompt-injection`, `skill-security` |
| `upload-sarif`     | `false`               | Run a second pass in SARIF format and upload it to GitHub Code Scanning (needs `security-events: write`, see below)         |
| `sarif-file`       | `sigil-results.sarif` | Where the SARIF report is written when `upload-sarif` is `true` (relative to the workspace)                                 |
| `api-key`          | —                     | Sigil cloud API key for threat intelligence enrichment (key issuance is not yet available — leave unset)                     |

The action always runs the scan with `--format json` internally; there is no `format` input. Use `upload-sarif` for SARIF output.

### Outputs

| Output           | Description                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| `verdict`        | Scan verdict: `clean`, `low`, `medium`, `high`, `critical` (`error` if the scanner produced no parseable output)    |
| `risk-score`     | Numeric risk score                                                                                                 |
| `findings-count` | Number of findings                                                                                                 |
| `grade`          | Letter grade `A`–`F` derived from the verdict (A no findings, B low-severity only, C medium, D high, F critical)    |
| `badge`          | Ready-to-paste shields.io Markdown badge for the grade (empty when no grade was produced)                          |
| `sarif-file`     | Path of the SARIF report (only set when `upload-sarif` is `true`)                                                  |

Example — use the grade in a later step:

```yaml
- uses: NOMARJ/sigil@main
  id: sigil
  with:
    path: .

- run: |
    echo "Sigil grade: ${{ steps.sigil.outputs.grade }}"
    echo "${{ steps.sigil.outputs.badge }}" >> "$GITHUB_STEP_SUMMARY"
```

### SARIF Upload

Set `upload-sarif: true` to publish Sigil findings to GitHub Code Scanning, which annotates
the affected lines directly in the pull request diff. The action runs a second `sigil scan
--format sarif` pass, writes it to `sarif-file`, and uploads it with
`github/codeql-action/upload-sarif` under the category `sigil`. The upload step is guarded
with `always()`, so findings are published even when the threshold check fails the job.

The calling job **must** grant `security-events: write` (Code Scanning rejects the upload
otherwise). Private repositories also need `actions: read`:

```yaml
name: Sigil Security Scan
on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read # private repositories only
    steps:
      - uses: actions/checkout@v4

      - uses: NOMARJ/sigil@main
        with:
          path: .
          threshold: medium
          upload-sarif: true
          sarif-file: sigil-results.sarif
```

The SARIF pass never fails the job on its own — only the JSON pass and the `threshold` /
`fail-on-findings` inputs decide the exit status. If the SARIF pass cannot produce a valid
document, an empty SARIF file is written so the upload step still succeeds.

### Scan Only Changed Files

Scan only the files changed in a pull request:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed
        run: |
          echo "files=$(git diff --name-only origin/main...HEAD | tr '\n' ' ')" >> $GITHUB_OUTPUT

      - uses: NOMARJ/sigil@main
        with:
          path: ${{ steps.changed.outputs.files }}
          threshold: low
```

### Block Merge on High-Risk Findings

Require Sigil scans to pass before merging. Add Sigil as a required status check:

1. Add the workflow above to your repository
2. Go to **Settings > Branches > Branch protection rules**
3. Enable **Require status checks to pass before merging**
4. Select the Sigil scan job

### Authenticated Scans in CI

The action accepts an `api-key` input for cloud threat-intelligence enrichment. API key
issuance is not yet available from the dashboard, so this currently stays unset — all
scan phases run fully offline without it. Once keys ship, pass one as a repository secret:

```yaml
- uses: NOMARJ/sigil@main
  with:
    path: .
    api-key: ${{ secrets.SIGIL_API_KEY }}
```

---

## GitLab CI

Sigil provides a CI template that you can include in your `.gitlab-ci.yml`.

### Basic Setup

```yaml
include:
  - remote: "https://raw.githubusercontent.com/NOMARJ/sigil/main/.gitlab-ci-template.yml"

sigil-scan:
  stage: test
  extends: .sigil-scan
  variables:
    SIGIL_SCAN_PATH: "."
    SIGIL_THRESHOLD: "medium"
    SIGIL_FAIL_ON_FINDINGS: "true"
```

### Variables

| Variable                 | Default  | Description                       |
| ------------------------ | -------- | --------------------------------- |
| `SIGIL_SCAN_PATH`        | `.`      | Directory to scan                 |
| `SIGIL_THRESHOLD`        | `medium` | Minimum severity to report        |
| `SIGIL_FAIL_ON_FINDINGS` | `true`   | Fail the job on findings          |
| `SIGIL_FORMAT`           | `text`   | Output format                     |

### Artifacts

The scan report is saved as a job artifact:

```yaml
sigil-scan:
  extends: .sigil-scan
  artifacts:
    paths:
      - sigil-report.*
    when: always
```

---

## Generic CI (Jenkins, CircleCI, Bitbucket)

For any CI system that can run shell commands:

### 1. Install Sigil

```bash
curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh
sh install.sh
```

Or use the Docker image:

```bash
docker pull ghcr.io/nomarj/sigil:1.2.1
```

### 2. Run the Scan

```bash
sigil scan . --format json > sigil-report.json
```

### 3. Check the Exit Code

| Exit Code | Verdict     | Recommended Action          |
| --------- | ----------- | --------------------------- |
| `0`       | CLEAN       | Pipeline passes             |
| `4`       | LOW_RISK    | Pass with warning           |
| `3`       | MEDIUM_RISK | Pass or fail (configurable) |
| `2`       | HIGH_RISK   | Fail the pipeline           |
| `1`       | CRITICAL    | Fail the pipeline           |

```bash
sigil scan .
EXIT_CODE=$?

if [ $EXIT_CODE -ge 2 ]; then
  echo "Sigil found high-risk issues — blocking pipeline"
  exit 1
fi
```

### Jenkins Example

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh && sh install.sh'
                sh '''
                    sigil scan . --format json > sigil-report.json
                    EXIT_CODE=$?
                    if [ $EXIT_CODE -ge 2 ]; then
                        echo "High-risk findings detected"
                        exit 1
                    fi
                '''
                archiveArtifacts artifacts: 'sigil-report.json', allowEmptyArchive: true
            }
        }
    }
}
```

### CircleCI Example

```yaml
version: 2.1

jobs:
  sigil-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install Sigil
          command: curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh && sh install.sh
      - run:
          name: Run security scan
          command: |
            sigil scan . --format json > sigil-report.json
            EXIT_CODE=$?
            if [ $EXIT_CODE -ge 2 ]; then
              echo "High-risk findings detected"
              exit 1
            fi
      - store_artifacts:
          path: sigil-report.json

workflows:
  security:
    jobs:
      - sigil-scan
```

### Bitbucket Pipelines Example

```yaml
pipelines:
  default:
    - step:
        name: Sigil Security Scan
        script:
          - curl -fsSLO https://raw.githubusercontent.com/NOMARJ/sigil/main/install.sh && sh install.sh
          - sigil scan . --format json > sigil-report.json
          - |
            EXIT_CODE=$?
            if [ $EXIT_CODE -ge 2 ]; then
              echo "High-risk findings detected"
              exit 1
            fi
        artifacts:
          - sigil-report.json
```

---

## Docker-Based CI

Use the Sigil Docker image directly in CI:

### Volume Mount

```bash
docker run --rm \
  -v "$(pwd):/workspace" \
  ghcr.io/nomarj/sigil:1.2.1 \
  scan /workspace --format json
```

### Multi-Stage Build Integration

Add a scan stage to your Dockerfile:

```dockerfile
# Build stage
FROM node:20 AS builder
COPY . /app
WORKDIR /app
RUN npm install && npm run build

# Security scan stage
FROM ghcr.io/nomarj/sigil:1.2.1 AS scanner
COPY --from=builder /app /scan
RUN sigil scan /scan --format json > /scan/sigil-report.json

# Production stage
FROM node:20-slim
COPY --from=builder /app/dist /app
COPY --from=scanner /scan/sigil-report.json /app/
CMD ["node", "/app/index.js"]
```

---

## Alert Notifications

Configure Sigil to send alerts when CI scans find issues.

### Slack Webhook

```bash
curl -X POST \
  -H "Authorization: Bearer $SIGIL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "slack",
    "name": "CI Alerts",
    "config": {
      "webhook_url": "https://hooks.slack.com/services/T.../B.../..."
    },
    "events": ["scan.high", "scan.critical"]
  }' \
  https://api.sigilsec.ai/v1/settings/alerts
```

### Email Alerts

```bash
curl -X POST \
  -H "Authorization: Bearer $SIGIL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "email",
    "name": "Security Team",
    "config": {
      "email": "security@company.com"
    },
    "events": ["scan.high", "scan.critical"]
  }' \
  https://api.sigilsec.ai/v1/settings/alerts
```

### Generic Webhook

```bash
curl -X POST \
  -H "Authorization: Bearer $SIGIL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "webhook",
    "name": "Custom Integration",
    "config": {
      "url": "https://your-service.com/webhook",
      "secret": "your-webhook-secret"
    },
    "events": ["scan.high", "scan.critical"]
  }' \
  https://api.sigilsec.ai/v1/settings/alerts
```

---

## Output Formats

### Text (Default)

Human-readable output with colored verdicts and formatted findings.

### JSON

Machine-readable output for programmatic processing:

```json
{
  "verdict": "MEDIUM_RISK",
  "score": 12,
  "findings": [
    {
      "severity": "high",
      "phase": "code_patterns",
      "rule": "eval_usage",
      "file": "src/parser.py",
      "line": 42,
      "snippet": "result = eval(expression)",
      "weight": 5
    }
  ],
  "files_scanned": 47,
  "duration_ms": 850
}
```

### SARIF

Static Analysis Results Interchange Format, compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF tools:

```bash
sigil scan . --format sarif > results.sarif
```

---

## See Also

- [CLI Command Reference](cli.md) — Exit codes and command flags
- [Configuration Guide](configuration.md) — Environment variables and policies
- [Getting Started](getting-started.md) — Installation and first scan
- [Architecture](architecture.md) — How the scan engine works
