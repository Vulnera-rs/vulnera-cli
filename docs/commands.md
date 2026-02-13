# Command Reference

## Global Flags

- `--format <table|json|plain|sarif>`
- `--ci`
- `--offline`
- `--verbose`
- `--quiet`
- `--config <PATH>`
- `--server <URL>`

## Core Commands

```bash
vulnera analyze [PATH]
vulnera sast [PATH]
vulnera secrets [PATH]
vulnera api [PATH]
vulnera deps [PATH]
```

## Auth & Quota

```bash
vulnera auth login [--api-key <KEY>]
vulnera auth status
vulnera auth logout
vulnera quota status
```

## Fix Generation

```bash
vulnera generate-fix \
  --vulnerability <ID> \
  --code <PATH> \
  --line <LINE>

vulnera sast [PATH] --fix
```

## Config + Hooks

```bash
vulnera config show
vulnera config init
vulnera config set <KEY> <VAL>

vulnera config hooks install [PATH] [--backend git|pre-commit] [--with-deps] [--min-severity high] [--force]
vulnera config hooks status [PATH]
vulnera config hooks remove [PATH] [--backend git|pre-commit]
```
