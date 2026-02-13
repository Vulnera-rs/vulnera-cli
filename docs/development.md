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
