# Development & Hooks

## Build and Validate

```bash
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Hook Setup

### Native Git Hook

```bash
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

### pre-commit Framework

```bash
pipx install pre-commit
pre-commit install
pre-commit run --all-files
```

## What the Hook Runs

- `cargo fmt --all --check`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --test cli_tests`

## Release Pipeline

The CLI repository has its own release pipeline at `.github/workflows/release.yml`.

- Trigger: push tag matching `v*.*.*` (for example: `v0.2.2`)
- Artifact build script: `.github/scripts/distribute.sh`
- Outputs per target:
	- `vulnera-cli-<tag>-<target>.tar.gz`
	- `vulnera-cli-<tag>-<target>.sha256`

Manual local packaging:

```bash
chmod +x .github/scripts/distribute.sh
.github/scripts/distribute.sh v0.2.2 x86_64-unknown-linux-gnu
```
