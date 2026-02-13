# Quick Start

## Install

```bash
cargo install vulnera-cli
```

## First Scan

```bash
vulnera analyze .
```

## Module-Only Scans

```bash
vulnera sast .
vulnera secrets .
vulnera api .
vulnera deps .
```

## Authentication

```bash
vulnera auth login --api-key <KEY>
vulnera auth status
```

## Output Formats

```bash
vulnera analyze . --format table
vulnera analyze . --format json
vulnera analyze . --format sarif > results.sarif
```

## Remediation

```bash
# Single finding
vulnera generate-fix --vulnerability <ID> --code <PATH> --line <LINE>

# Bulk SAST remediation suggestions and LLM fixes
vulnera sast . --fix
```
