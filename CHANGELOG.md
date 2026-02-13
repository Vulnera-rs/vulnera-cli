# Changelog

All notable changes to `vulnera-cli` are documented here.
The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [0.2.1] - 2026-02-13

### Added
- Project hook management commands:
  - `vulnera config hooks install`
  - `vulnera config hooks status`
  - `vulnera config hooks remove`
- Hook backend selection for install (`git` or `pre-commit`) with idempotent managed blocks.
- Bulk LLM-backed remediation pipeline for `vulnera sast --fix`.
- SAST remediation aggregation in outputs:
  - Generated LLM fixes
  - Built-in SAST suggestions
  - Dependency upgrade suggestions
- SARIF output enrichment for SAST findings with generated fixes.

### Changed
- Refactored command orchestration toward application use-cases to keep command modules thin.
- Centralized API client creation in `CliContext` for consistent behavior across commands.
- Improved watch-mode execution path with shared runner behavior.

### Fixed
- Eliminated the previous placeholder behavior for `sast --fix` and enabled real bulk generation.
- Cleaned strict clippy warnings in the affected CLI paths.

### Tests
- Added SAST remediation unit coverage in `application/use_cases/sast_fix.rs`.
- Expanded CLI smoke tests for `config hooks` subcommands.

## [0.2.0] - 2026-02-9

### Added
- Initial standalone `vulnera-cli` release with offline-first scanning modules and server-backed capabilities.
