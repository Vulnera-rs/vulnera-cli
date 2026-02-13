# Vulnera CLI

![Vulnera](https://img.shields.io/badge/Vulnera-CLI-blue)
![License](https://img.shields.io/badge/License-AGPL--3.0-blue)
![Rust](https://img.shields.io/badge/Rust-1.75+-orange)

**Comprehensive vulnerability analysis from the command line.** Vulnera CLI provides offline-first security scanning for your codebase with four specialized analysis modules.

## Overview

Vulnera CLI is a standalone vulnerability scanner that combines:

- **Offline Analysis** (no network required): SAST, Secrets Detection, API Security
- **Online Analysis** (with optional server): Dependency Vulnerability Scanning

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
- **Code Fixes** — AI-powered fix suggestions (with API key)

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
  --skip-sast                 Skip static analysis
  --skip-secrets              Skip secret detection
  --skip-api                  Skip API security analysis
  --min-severity <LEVEL>      Minimum severity: critical, high, medium, low [default: low]
  --fail-on-vuln              Exit with code 1 if vulnerabilities found
  --changed-only              Only analyze changed files (requires git)
  --exclude <PATTERNS>        Exclude glob patterns (comma-separated)
  --watch                     Continuous scanning on file changes
```

#### `sast [PATH]`

Static application security testing (offline).

```bash
vulnera sast . [OPTIONS]
  --min-severity <LEVEL>
  --exclude <PATTERNS>
```

#### `secrets [PATH]`

Detect hardcoded credentials and secrets (offline).

```bash
vulnera secrets . [OPTIONS]
  --min-severity <LEVEL>
  --exclude <PATTERNS>
```

#### `api [PATH]`

Analyze API endpoints for security issues (offline).

```bash
vulnera api . [OPTIONS]
  --min-severity <LEVEL>
```

#### `deps [PATH]`

Scan dependencies for known vulnerabilities (requires server).

```bash
vulnera deps . [OPTIONS]
  --skip-cache                Ignore cached results
  --compact                   Compact output format
```

#### `generate-fix`

Generate an AI-assisted fix for a specific vulnerability (requires server + authentication).

```bash
vulnera generate-fix \
  --vulnerability <ID> \
  --code <PATH> \
  --line <LINE> \
  --description <TEXT> \
  --language <LANG>
```

#### `quota`

Manage and check quota usage.

```bash
vulnera quota status              Show remaining requests
vulnera quota reset               Reset quota (debug only)
```

#### `auth`

Authentication and credential management.

```bash
vulnera auth login              Interactive login
vulnera auth login --api-key <KEY>
vulnera auth logout             Clear stored credentials
vulnera auth status             Show authentication status
vulnera auth info               Show credential storage location
```

#### `config`

Manage configuration.

```bash
vulnera config show             Display current configuration
vulnera config init             Initialize config file
vulnera config set <KEY> <VAL>  Set configuration value
```

## Configuration

Vulnera CLI reads configuration from multiple sources in order of precedence:

1. Command-line flags
2. Environment variables
3. Configuration file (`~/.vulnera/config.toml`)
4. Default values

### Configuration File

Create `~/.vulnera/config.toml`:

```toml
# Server settings
[server]
url = "https://api.vulnera.studio"
timeout_ms = 30000
retry_attempts = 3

# Analysis settings
[analysis]
min_severity = "medium"
fail_on_vuln = false
cache_results = true
cache_ttl_hours = 24

# SAST configuration
[sast]
enabled = true
severity_level = "medium"
ignore_patterns = ["**/test/**", "**/vendor/**"]

# Secrets detection
[secrets]
enabled = true
entropy_threshold = 3.5
ignore_patterns = ["**/test/**", "**/docs/**"]

# API security
[api]
enabled = true
check_authentication = true
check_authorization = true

# Credential storage
[credentials]
storage_method = "keyring"  # Options: keyring, encrypted_file
encryption_key_path = "~/.vulnera/key"

# Output
[output]
format = "table"
colors = true
verbose = false
quiet = false
```

### Environment Variables

```bash
# Server
export VULNERA_SERVER_URL="https://api.vulnera.studio"

# Authentication
export VULNERA_API_KEY="sk_live_xxxxxxxxxxxxx"

# Mode flags
export VULNERA_CI="true"           # CI mode
export VULNERA_OFFLINE="true"      # Offline mode

# Logging
export RUST_LOG="info,vulnera_cli=debug"
```

## Output Formats

### Table Format (Default)

```
┌─────────────────────────────────────────────────────────┐
│ VULNERABILITIES FOUND: 3                                │
├─────────────────────────────────────────────────────────┤
│ Severity │ Package    │ Version │ Issue           │ Fix │
├──────────┼────────────┼─────────┼─────────────────┼─────┤
│ HIGH     │ lodash     │ 4.17.20 │ Prototype Pollu │ Yes │
│ MEDIUM   │ minimist   │ 1.2.3   │ Argument Inject │ Yes │
│ LOW      │ normalize  │ 1.1.0   │ Path Traversal  │ No  │
└─────────────────────────────────────────────────────────┘
```

### JSON Format

```json
{
  "path": "/workspace",
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "severity": "high",
      "package": "lodash",
      "version": "4.17.20",
      "description": "Lodash versions < 4.17.21 are vulnerable to...",
      "module": "deps",
      "fix_available": true,
      "fixed_version": "4.17.21"
    }
  ],
  "summary": {
    "total": 3,
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 1
  }
}
```

### SARIF Format

SARIF (Static Analysis Results Interchange Format) for IDE and CI integration:

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Vulnera CLI",
          "version": "0.2.0"
        }
      },
      "results": [
        {
          "ruleId": "CVE-2021-23337",
          "message": {
            "text": "Prototype Pollution in lodash < 4.17.21"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "package.json"
                }
              }
            }
          ],
          "level": "warning"
        }
      ]
    }
  ]
}
```

## Authentication & Quota

### Free Tier

- **Limit**: 10 requests/day
- **Modules**: Offline analysis only
- **Storage**: No credential storage

### Authenticated (API Key)

- **Limit**: 40 requests/day
- **Modules**: All modules including dependencies
- **Storage**: OS keyring or encrypted file
- **Features**: Priority support, code fix generation

### Quota Management

```bash
# Check remaining quota
vulnera quota status

# Output:
# Used:      8/10
# Remaining: 2 requests
# Resets at: 2024-01-15 00:00:00 UTC

# Get API key
# 1. Visit https://vulnera.studio/account
# 2. Generate API key
# 3. Run: vulnera auth login --api-key sk_live_xxxxx
```

## Credential Storage

Vulnera CLI stores credentials securely using:

1. **OS Keyring** (Preferred)
   - macOS: Keychain
   - Linux: Secret Service / Pass
   - Windows: Credential Manager

2. **Encrypted File** (Fallback)
   - Location: `~/.vulnera/credentials.enc`
   - Encryption: AES-256-GCM
   - Key: Stored in `~/.vulnera/key`

Check credential storage:

```bash
vulnera auth info

# Output:
# Storage Method: OS Keyring (macOS Keychain)
# Location: ~/Library/Keychains/login.keychain-db
# Encrypted Fallback: ~/.vulnera/credentials.enc
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Vulnera Scan
        uses: Vulnera-rs/vulnera-cli@v1
        with:
          path: .
          format: sarif
          fail-on-vuln: true
          min-severity: high
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

## Exit Codes

For CI/CD integration, Vulnera returns specific exit codes:

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| `0`  | Success - no vulnerabilities found            |
| `1`  | Vulnerabilities found (with `--fail-on-vuln`) |
| `2`  | Configuration or input error                  |
| `3`  | Network error (when online mode required)     |
| `4`  | Quota exceeded                                |
| `5`  | Authentication required but not provided      |
| `99` | Internal error                                |

## Performance

### Analysis Speed

On a medium-sized project (100K lines of code):

```
SAST Analysis:      ~2.3s
Secrets Detection:  ~0.8s
API Security:       ~1.2s
Dependencies:       ~5.0s (with network)
─────────────────────────
Total (offline):    ~4.3s
Total (online):     ~9.3s
```

### Memory Usage

- **Offline mode**: ~45MB
- **With dependencies**: ~120MB
- **Watch mode**: +30MB per scan

### Optimization Tips

1. Use `--skip-*` flags to disable unused modules
2. Enable `--changed-only` in development
3. Use `--min-severity` to reduce output
4. Enable caching for dependencies: `cache_results = true`

## Troubleshooting

### Issue: "API key required but not provided"

```bash
# Solution 1: Login interactively
vulnera auth login

# Solution 2: Provide via environment
export VULNERA_API_KEY="sk_live_xxxxx"

# Solution 3: Use --server with offline flag
vulnera analyze . --offline
```

### Issue: "Quota exceeded"

```bash
# Check quota status
vulnera quota status

# Upgrade to API key for higher limits
vulnera auth login --api-key sk_live_xxxxx

# Or wait for quota reset (24 hours)
```

### Issue: "Network error connecting to server"

```bash
# Run in offline mode (skip dependency analysis)
vulnera analyze . --offline

# Or specify custom server URL
vulnera analyze . --server https://custom-vulnera-instance.com

# Check server health
curl https://api.vulnera.studio/health
```

### Issue: "Permission denied for keyring"

```bash
# Switch to encrypted file storage
vulnera config set credentials.storage_method encrypted_file

# Or provide API key via environment instead
export VULNERA_API_KEY="sk_live_xxxxx"
```

### Enable Debug Logging

```bash
export RUST_LOG="debug,vulnera_cli=trace"
vulnera analyze . --verbose
```

## Development

### Prerequisites

- Rust 1.75+
- Cargo

### Building from Source

```bash
git clone https://github.com/Vulnera-rs/vulnera-cli.git
cd vulnera-cli

# Build
cargo build --release

# Test
cargo test

# Run CLI
cargo run -- analyze .

# Check code quality
cargo clippy
cargo fmt --check
```

### Developer Ergonomics (Hooks)

Use one of the following hook setups to catch issues before pushing:

```bash
# Option A: Python pre-commit framework
pipx install pre-commit
pre-commit install
pre-commit run --all-files

# Option B: Native git hook (no Python dependency)
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

Both hook setups run:

- `cargo fmt --all --check`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --test cli_tests`

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_finding_severity_level

# With output
cargo test -- --nocapture

# Integration tests
cargo test --test '*' -- --test-threads=1
```

### Project Structure

```
vulnera-cli/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library root, CLI arg parsing
│   ├── executor.rs          # Analysis module orchestrator
│   ├── api_client.rs        # Server API communication
│   ├── context.rs           # CLI service context
│   ├── credentials.rs       # Credential storage & retrieval
│   ├── quota_tracker.rs     # Rate limit tracking
│   ├── output.rs            # Output formatting (table, JSON, SARIF)
│   ├── severity.rs          # Severity levels and filtering
│   ├── commands/
│   │   ├── analyze.rs       # Main analyze command
│   │   ├── sast.rs          # SAST analysis
│   │   ├── secrets.rs       # Secret detection
│   │   ├── api.rs           # API security analysis
│   │   ├── deps.rs          # Dependency scanning
│   │   ├── auth.rs          # Authentication management
│   │   ├── quota.rs         # Quota status
│   │   ├── config.rs        # Configuration management
│   │   └── mod.rs
│   └── ...
├── tests/                   # Integration tests
├── Cargo.toml              # Dependencies
├── Cargo.lock              # Locked versions
├── .cargo/config.toml      # Cargo configuration
└── README.md
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Code Style

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check

# Lint with Clippy
cargo clippy --all-targets --all-features -- -D warnings
```

## License

Licensed under the GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE) for details.

## Support

- **Documentation**: https://docs.vulnera.studio/cli
- **Issues**: https://github.com/Vulnera-rs/vulnera-cli/issues
- **Discussions**: https://github.com/Vulnera-rs/vulnera-cli/discussions
- **Email**: support@vulnera.studio

## Roadmap

- [ ] Windows native credential storage support
- [ ] Custom rule definitions
- [ ] Policy enforcement and compliance reporting
- [ ] Integration with package managers (npm, pip, cargo)
- [ ] Real-time vulnerability notifications
- [ ] Automated remediation suggestions
- [ ] Container image scanning

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

**Made with ❤️ by the Vulnera Team**
