# Vulnera CLI

![Vulnera](https://img.shields.io/badge/Vulnera-CLI-blue)
![License](https://img.shields.io/badge/License-AGPL--3.0-blue)
![Rust](https://img.shields.io/badge/Rust-1.75+-orange)

**Comprehensive vulnerability analysis from the command line.** Vulnera CLI provides offline-first security scanning for your codebase with four specialized analysis modules.

## Overview

Vulnera CLI is a standalone vulnerability scanner that combines:

- **Offline Analysis** (no network required): SAST, Secrets Detection, API Security
- **Online Analysis** (with optional server): Dependency Vulnerability Scanning and more premium features


Perfect for CI/CD pipelines, local development, and air-gapped environments.

```
$ vulnera analyze .

  ╔═══════════════════════════════════════╗
  ║   ██╗   ██╗██╗   ██╗██╗     ███████╗  ║
  ║   ██║   ██║██║   ██║██║     ██╔════╝  ║
  ║   ██║   ██║██║   ██║██║     ███████╗  ║
  ║   ██║   ██║██║   ██║██║     ╚════██║  ║
  ║   ╚██████╔╝╚██████╔╝███████╗███████║  ║
  ║    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝  ║
  ║                                       ║
  ║  Comprehensive Vulnerability Scanner  ║
  ╚═══════════════════════════════════════╝

Scanning project in: /path/to/project
├─ SAST Analysis       [████████████████] 42 findings
├─ Secrets Detection   [████████████████] 5 findings
├─ API Security        [████████████████] 3 findings
└─ Dependencies        [████████████████] 12 vulnerabilities

Total: 62 issues found
  Critical: 3 | High: 8 | Medium: 15 | Low: 36
```

## Features

### 🔍 Analysis Modules

| Module           | Type                | Network | Speed  | Coverage                                     |
| ---------------- | ------------------- | ------- | ------ | -------------------------------------------- |
| **SAST**         | Static analysis     | Offline | Fast   | Code quality, logic bugs, injection flaws    |
| **Secrets**      | Credential scanning | Offline | Fast   | API keys, passwords, tokens, PII             |
| **API Security** | Endpoint analysis   | Offline | Fast   | Authentication, authorization, data exposure |
| **Dependencies** | CVE scanning        | Online  | Medium | Known vulnerabilities in packages            |

### ⚡ Key Capabilities

- **Zero Network Requirement** — Run all offline modules without internet
- **Machine-Readable Output** — JSON, SARIF, and plain text formats
- **CI/CD Ready** — Exit codes, non-interactive mode, quiet output
- **Quota Management** — 10 daily requests free, 40+ with API key
- **Credential Storage** — OS keyring with AES-256-GCM encrypted fallback
- **File Watching** — `--watch` mode for continuous scanning
- **Severity Filtering** — Report only critical/high issues
- **Smart Caching** — Cache dependency analysis results locally
- **Code Fixes** — AI-powered fix suggestions 
- **Pre-commit Hooks** — Easy integration with Git hooks for automated scanning

## Installation

### From Cargo

```bash
cargo install vulnera-cli
```

### From Source

```bash
git clone https://github.com/Vulnera-rs/vulnera-cli.git
cd vulnera-cli
cargo install --path .
```

### Docker

```bash
docker run --rm -v "$(pwd):/workspace" vulnera/cli:latest analyze /workspace
```

### Homebrew (coming soon)

```bash
brew install vulnera-cli
```

## Quick Start

### 1. Analyze Your Project (Offline)

```bash
# Scan current directory
vulnera analyze .

# Scan specific path
vulnera analyze /path/to/project

# Only offline modules (no network)
vulnera analyze . --offline

# Fail if vulnerabilities found (for CI)
vulnera analyze . --fail-on-vuln
```

### 2. Run Individual Modules

```bash
# Static analysis only
vulnera sast .

# Detect hardcoded secrets
vulnera secrets .

# Check API endpoints
vulnera api .

# Scan dependencies (requires internet)
vulnera deps .
```

### 3. Authenticate for Higher Limits

```bash
# Login with API key (interactive prompt)
vulnera auth login

# Or provide key directly
vulnera auth login --api-key sk_live_xxxxxxxxxxxxx

# Check authentication status
vulnera auth status

# Logout
vulnera auth logout
```

### 4. Format Output for Different Purposes

```bash
# Pretty table (default)
vulnera analyze . --format table

# Machine-readable JSON
vulnera analyze . --format json | jq '.summary'

# Plain text (minimal formatting)
vulnera analyze . --format plain

# SARIF for IDE integration
vulnera analyze . --format sarif > results.sarif
```

## Usage Examples

### CI/CD Integration

```bash
# GitHub Actions
- name: Run Vulnera Scan
  run: |
    vulnera analyze . \
      --format sarif \
      --fail-on-vuln \
      --min-severity high
  env:
    VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
    VULNERA_CI: "true"

# Exit code 1 if vulnerabilities found
if [ $? -eq 1 ]; then
  echo "Security vulnerabilities detected"
  exit 1
fi
```

### Local Development

```bash
# Watch mode: continuous scanning on file changes
vulnera analyze . --watch

# Only check changed files (requires git)
vulnera analyze . --changed-only

# Exclude test/vendor directories
vulnera analyze . --exclude "tests/*,vendor/*"
```

### Security Gates

```bash
# Only report critical/high severity
vulnera analyze . --min-severity high --fail-on-vuln

# Generate compliance report
vulnera analyze . --format json > scan-report.json

# Check quota before running
vulnera quota status
```

### AI-Powered Fixes (Premium)

```bash
# Generate code fix for specific vulnerability
vulnera generate-fix \
  --vulnerability CVE-2024-1234 \
  --code "vulnerable_code.rs" \
  --line 42 \
  --description "Use safe parsing instead of eval" \
  --language rust
```

Arguments:

- `--vulnerability <ID>`: Vulnerability identifier (e.g., CVE)
- `--code <PATH>`: Path to the vulnerable file
- `--line <LINE>`: Line number of the issue
- `--description <TEXT>`: Optional description to improve fix quality
- `--language <LANG>`: Optional language override (auto-detected if omitted)

## Command Reference

### Global Flags

```
--format <FORMAT>           Output format: table, json, plain, sarif [default: table]
--ci                        CI mode: no prompts, exit codes for automation
--offline                   Force offline mode (skip network requests)
--verbose (-v)              Enable verbose logging
--quiet (-q)                Suppress all output except errors
--config <PATH>             Configuration file path
--server <URL>              Custom server URL for API calls
--help (-h)                 Show help message
--version                   Show version
```

### Commands

#### `analyze [PATH]`

Run comprehensive vulnerability analysis.

```bash
vulnera analyze . [OPTIONS]

OPTIONS:
  --skip-deps                 Skip dependency vulnerability scanning
  # Vulnera CLI

  Offline-first security scanner for code, secrets, APIs, and dependencies.

  ## Quick Start

  ```bash
  cargo install vulnera-cli
  vulnera analyze .
  ```

  ## Docs

  - [CLI docs index](docs/README.md)
  - [Quick start](docs/quick-start.md)
  - [Command reference](docs/commands.md)
  - [Development and hooks](docs/development.md)

  ## Highlights

  - Offline modules: `sast`, `secrets`, `api`
  - Online modules: `deps`, `generate-fix`, `sast --fix`
  - Output formats: `table`, `json`, `plain`, `sarif`
  - Hook management: `vulnera config hooks install|status|remove`

  ## Changelog

  - See [CHANGELOG.md](CHANGELOG.md)

  ## License

  AGPL-3.0-or-later.
Analyze API endpoints for security issues (offline).
