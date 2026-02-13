//! Config Command - Configuration management
//!
//! View and modify CLI configuration.

use std::path::PathBuf;
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use directories::ProjectDirs;
use serde::Serialize;

use crate::Cli;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::OutputFormat;

/// Arguments for the config command
#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Show current configuration
    Show,
    /// Show configuration file path
    Path,
    /// Set a configuration value
    Set(SetArgs),
    /// Get a configuration value
    Get(GetArgs),
    /// Reset configuration to defaults
    Reset,
    /// Initialize a new configuration file
    Init(InitArgs),
    /// Manage project pre-commit hooks for vulnera scans
    Hooks(HooksArgs),
}

#[derive(Args, Debug)]
pub struct HooksArgs {
    #[command(subcommand)]
    pub command: HooksCommand,
}

#[derive(Subcommand, Debug)]
pub enum HooksCommand {
    /// Install project hook(s)
    Install(InstallHooksArgs),
    /// Show hook status in current project
    Status(HookStatusArgs),
    /// Remove project hook(s)
    Remove(RemoveHooksArgs),
}

#[derive(Args, Debug)]
pub struct InstallHooksArgs {
    /// Project path (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Hook backend: native git hook or pre-commit framework
    #[arg(long, value_enum, default_value = "git")]
    pub backend: HookBackend,

    /// Include dependency scanning (online). Disabled by default for fast local hooks.
    #[arg(long)]
    pub with_deps: bool,

    /// Minimum severity gate for the hook
    #[arg(long, default_value = "high")]
    pub min_severity: String,

    /// Overwrite existing managed hook block
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct HookStatusArgs {
    /// Project path (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct RemoveHooksArgs {
    /// Project path (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Hook backend to remove
    #[arg(long, value_enum, default_value = "git")]
    pub backend: HookBackend,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum HookBackend {
    Git,
    PreCommit,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// Configuration key (e.g., "server.url", "analysis.timeout")
    pub key: String,
    /// Value to set
    pub value: String,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Configuration key to retrieve
    pub key: String,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Create config in project directory instead of user config
    #[arg(long)]
    pub local: bool,

    /// Overwrite existing configuration
    #[arg(long)]
    pub force: bool,
}

/// Configuration info for JSON output
#[derive(Debug, Serialize)]
pub struct ConfigInfo {
    pub config_file: Option<PathBuf>,
    pub values: serde_json::Value,
}

/// Run the config command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &ConfigArgs) -> Result<i32> {
    match &args.command {
        ConfigCommand::Show => show_config(ctx, cli).await,
        ConfigCommand::Path => show_path(ctx, cli).await,
        ConfigCommand::Set(set_args) => set_config(ctx, cli, set_args).await,
        ConfigCommand::Get(get_args) => get_config(ctx, cli, get_args).await,
        ConfigCommand::Reset => reset_config(ctx, cli).await,
        ConfigCommand::Init(init_args) => init_config(ctx, cli, init_args).await,
        ConfigCommand::Hooks(hook_args) => hooks(ctx, cli, hook_args).await,
    }
}

async fn hooks(ctx: &CliContext, _cli: &Cli, args: &HooksArgs) -> Result<i32> {
    match &args.command {
        HooksCommand::Install(install) => install_hooks(ctx, install).await,
        HooksCommand::Status(status) => hook_status(ctx, status).await,
        HooksCommand::Remove(remove) => remove_hooks(ctx, remove).await,
    }
}

/// Show current configuration
async fn show_config(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    match ctx.output.format() {
        OutputFormat::Json => {
            let config_value = serde_json::to_value(&*ctx.config)?;
            ctx.output.json(&config_value)?;
        }
        OutputFormat::Table | OutputFormat::Plain | OutputFormat::Sarif => {
            ctx.output.header("Current Configuration");

            // Server settings
            ctx.output.print("\n[Server]");
            ctx.output
                .print(&format!("  host: {}", ctx.config.server.host));
            ctx.output
                .print(&format!("  port: {}", ctx.config.server.port));

            // Analysis settings
            ctx.output.print("\n[Analysis]");
            ctx.output.print(&format!(
                "  max_concurrent_packages: {}",
                ctx.config.analysis.max_concurrent_packages
            ));

            // Cache settings
            ctx.output.print("\n[Cache]");
            ctx.output.print(&format!(
                "  dragonfly_url: {}",
                ctx.config.cache.dragonfly_url
            ));

            // Rate limit settings
            ctx.output.print("\n[Rate Limits]");
            ctx.output.print(&format!(
                "  enabled: {}",
                ctx.config.server.rate_limit.enabled
            ));
            ctx.output.print(&format!(
                "  storage_backend: {:?}",
                ctx.config.server.rate_limit.storage_backend
            ));
            ctx.output.print("\n  API Key tier:");
            ctx.output.print(&format!(
                "    requests_per_minute: {}",
                ctx.config
                    .server
                    .rate_limit
                    .tiers
                    .api_key
                    .requests_per_minute
            ));
            ctx.output.print(&format!(
                "    requests_per_hour: {}",
                ctx.config.server.rate_limit.tiers.api_key.requests_per_hour
            ));
            ctx.output.print("\n  Authenticated tier:");
            ctx.output.print(&format!(
                "    requests_per_minute: {}",
                ctx.config
                    .server
                    .rate_limit
                    .tiers
                    .authenticated
                    .requests_per_minute
            ));
            ctx.output.print("\n  Anonymous tier:");
            ctx.output.print(&format!(
                "    requests_per_minute: {}",
                ctx.config
                    .server
                    .rate_limit
                    .tiers
                    .anonymous
                    .requests_per_minute
            ));
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Show configuration file path
async fn show_path(ctx: &CliContext, _cli: &Cli) -> Result<i32> {
    let config_paths = get_config_paths();

    ctx.output.header("Configuration File Locations");

    ctx.output.print("\nSearch order (first found is used):");
    for (i, path) in config_paths.iter().enumerate() {
        let exists = path.exists();
        let marker = if exists { "✓" } else { " " };
        ctx.output
            .print(&format!("  {} {}. {:?}", marker, i + 1, path));
    }

    ctx.output.print("\nEnvironment variables:");
    ctx.output.print("  VULNERA__* - Override any config value");
    ctx.output.print("  Example: VULNERA__SERVER__PORT=9000");

    Ok(exit_codes::SUCCESS)
}

/// Get configuration file search paths
fn get_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. Current directory
    paths.push(PathBuf::from(".vulnera.toml"));
    paths.push(PathBuf::from("vulnera.toml"));

    // 2. User config directory
    if let Some(dirs) = ProjectDirs::from("dev", "vulnera", "vulnera-cli") {
        paths.push(dirs.config_dir().join("config.toml"));
    }

    // 3. XDG config
    if let Some(config_dir) = dirs::config_dir() {
        paths.push(config_dir.join("vulnera").join("config.toml"));
    }

    // 4. Home directory
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".vulnera").join("config.toml"));
        paths.push(home.join(".config").join("vulnera").join("config.toml"));
    }

    paths
}

/// Set a configuration value
async fn set_config(ctx: &CliContext, _cli: &Cli, args: &SetArgs) -> Result<i32> {
    // Parse key path
    let parts: Vec<&str> = args.key.split('.').collect();
    if parts.is_empty() {
        ctx.output.error("Invalid configuration key");
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // Get user config path
    let config_path = get_user_config_path();

    // Load existing config or create new
    let mut config: toml::Value = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        toml::from_str(&content)?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    // Navigate to the correct location and set value
    set_nested_value(&mut config, &parts, &args.value)?;

    // Write config back
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let content = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, content)?;

    ctx.output
        .success(&format!("Set {} = {}", args.key, args.value));
    ctx.output
        .info(&format!("Config saved to {:?}", config_path));

    Ok(exit_codes::SUCCESS)
}

/// Get a configuration value
async fn get_config(ctx: &CliContext, _cli: &Cli, args: &GetArgs) -> Result<i32> {
    let config_value = serde_json::to_value(&*ctx.config)?;

    let parts: Vec<&str> = args.key.split('.').collect();
    let mut current = &config_value;

    for part in &parts {
        match current.get(part) {
            Some(v) => current = v,
            None => {
                ctx.output
                    .error(&format!("Configuration key not found: {}", args.key));
                return Ok(exit_codes::CONFIG_ERROR);
            }
        }
    }

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(current)?;
        }
        _ => {
            ctx.output.print(&format!("{} = {}", args.key, current));
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Reset configuration to defaults
async fn reset_config(ctx: &CliContext, cli: &Cli) -> Result<i32> {
    let config_path = get_user_config_path();

    if !config_path.exists() {
        ctx.output.info("No user configuration file to reset");
        return Ok(exit_codes::SUCCESS);
    }

    // Confirm in interactive mode
    if !cli.ci {
        let confirm = crate::output::confirm(
            "Are you sure you want to reset configuration to defaults?",
            false,
            cli.ci,
        )?;
        if !confirm {
            ctx.output.info("Reset cancelled");
            return Ok(exit_codes::SUCCESS);
        }
    }

    std::fs::remove_file(&config_path)?;
    ctx.output.success("Configuration reset to defaults");
    ctx.output.info(&format!("Removed: {:?}", config_path));

    Ok(exit_codes::SUCCESS)
}

/// Initialize a new configuration file
async fn init_config(ctx: &CliContext, _cli: &Cli, args: &InitArgs) -> Result<i32> {
    let config_path = if args.local {
        PathBuf::from(".vulnera.toml")
    } else {
        get_user_config_path()
    };

    if config_path.exists() && !args.force {
        ctx.output
            .error(&format!("Config file already exists: {:?}", config_path));
        ctx.output.info("Use --force to overwrite");
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // Create default config content
    let default_config = r#"# Vulnera CLI Configuration
# See https://vulnera.dev/docs/cli/configuration for full options

[server]
host = "https://api.vulnera.studio/"
port = 80

[analysis]
# Maximum concurrent packages to analyze
max_concurrent_packages = 10
# Timeout for analysis in seconds
timeout_seconds = 300

[output]
# Default output format: table, json, sarif
format = "table"
# Use colors in output
colors = true
"#;

    // Create parent directories
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&config_path, default_config)?;

    ctx.output
        .success(&format!("Created config file: {:?}", config_path));
    ctx.output
        .info("Edit this file to customize Vulnera CLI behavior");

    Ok(exit_codes::SUCCESS)
}

/// Get user config file path
fn get_user_config_path() -> PathBuf {
    if let Some(dirs) = ProjectDirs::from("dev", "vulnera", "vulnera-cli") {
        dirs.config_dir().join("config.toml")
    } else if let Some(home) = dirs::home_dir() {
        home.join(".vulnera").join("config.toml")
    } else {
        PathBuf::from(".vulnera.toml")
    }
}

/// Set a nested value in a TOML document
fn set_nested_value(root: &mut toml::Value, parts: &[&str], value: &str) -> Result<()> {
    if parts.is_empty() {
        return Ok(());
    }

    let mut current = root;

    // Navigate/create path to parent
    for part in &parts[..parts.len() - 1] {
        current = current
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("Invalid config structure"))?
            .entry(*part)
            .or_insert(toml::Value::Table(toml::map::Map::new()));
    }

    // Set the final value
    let table = current
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("Invalid config structure"))?;

    // Try to parse the value as the appropriate type
    let parsed_value = if value == "true" {
        toml::Value::Boolean(true)
    } else if value == "false" {
        toml::Value::Boolean(false)
    } else if let Ok(n) = value.parse::<i64>() {
        toml::Value::Integer(n)
    } else if let Ok(f) = value.parse::<f64>() {
        toml::Value::Float(f)
    } else {
        toml::Value::String(value.to_string())
    };

    table.insert(parts[parts.len() - 1].to_string(), parsed_value);

    Ok(())
}

const HOOK_BEGIN: &str = "# >>> vulnera hook start";
const HOOK_END: &str = "# <<< vulnera hook end";

async fn install_hooks(ctx: &CliContext, args: &InstallHooksArgs) -> Result<i32> {
    let project_path = resolve_project_path(&ctx.working_dir, &args.path);
    if !project_path.exists() {
        ctx.output
            .error(&format!("Project path does not exist: {:?}", project_path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    match args.backend {
        HookBackend::Git => install_git_hook(ctx, &project_path, args),
        HookBackend::PreCommit => install_precommit_hook(ctx, &project_path, args),
    }
}

fn install_git_hook(ctx: &CliContext, project_path: &Path, args: &InstallHooksArgs) -> Result<i32> {
    let Some(repo_root) = find_git_root(project_path) else {
        ctx.output.error("Not inside a git repository");
        return Ok(exit_codes::CONFIG_ERROR);
    };

    let hook_path = repo_root.join(".git").join("hooks").join("pre-commit");
    let existing = std::fs::read_to_string(&hook_path).unwrap_or_default();

    if existing.contains(HOOK_BEGIN) && !args.force {
        ctx.output
            .info("Vulnera git hook is already installed (use --force to replace)");
        return Ok(exit_codes::SUCCESS);
    }

    let command = build_hook_command(args);
    let managed_block = format!(
        "{HOOK_BEGIN}\nif ! command -v vulnera >/dev/null 2>&1; then\n  echo \"vulnera CLI not found in PATH\"\n  exit 1\nfi\nif ! {command}; then\n  HOOK_STATUS=$?\n  echo \"Vulnera hook blocked commit (exit $HOOK_STATUS)\"\n  exit $HOOK_STATUS\nfi\n{HOOK_END}\n"
    );

    let new_content = if existing.trim().is_empty() {
        format!("#!/usr/bin/env bash\nset -euo pipefail\n\n{managed_block}")
    } else {
        let stripped = strip_managed_block(&existing);
        format!("{}\n{}", stripped.trim_end(), managed_block)
    };

    if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&hook_path, new_content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    ctx.output.success("Installed git pre-commit hook");
    ctx.output
        .info(&format!("Hook path: {:?}", hook_path));
    Ok(exit_codes::SUCCESS)
}

fn install_precommit_hook(
    ctx: &CliContext,
    project_path: &Path,
    args: &InstallHooksArgs,
) -> Result<i32> {
    let config_path = project_path.join(".pre-commit-config.yaml");
    let existing = std::fs::read_to_string(&config_path).unwrap_or_default();

    if existing.contains("id: vulnera-scan") && !args.force {
        ctx.output
            .info("Vulnera pre-commit hook is already present (use --force to replace)");
        return Ok(exit_codes::SUCCESS);
    }

    let command = build_hook_command(args);
    let block = format!(
        "{HOOK_BEGIN}\nrepos:\n  - repo: local\n    hooks:\n      - id: vulnera-scan\n        name: vulnera scan\n        entry: {command}\n        language: system\n        pass_filenames: false\n{HOOK_END}\n"
    );

    let new_content = if existing.trim().is_empty() {
        block
    } else {
        let stripped = strip_managed_block(&existing);
        format!("{}\n\n{}", stripped.trim_end(), block)
    };

    std::fs::write(&config_path, new_content)?;

    ctx.output
        .success("Updated .pre-commit-config.yaml with vulnera hook");
    ctx.output.info(
        "Run 'pre-commit install' in this project to enable the hook",
    );
    Ok(exit_codes::SUCCESS)
}

async fn hook_status(ctx: &CliContext, args: &HookStatusArgs) -> Result<i32> {
    let project_path = resolve_project_path(&ctx.working_dir, &args.path);
    let repo_root = find_git_root(&project_path);

    let git_hook_status = repo_root
        .as_ref()
        .map(|root| root.join(".git").join("hooks").join("pre-commit"))
        .filter(|p| p.exists())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|content| content.contains(HOOK_BEGIN));

    let precommit_cfg = project_path.join(".pre-commit-config.yaml");
    let precommit_status = precommit_cfg.exists()
        && std::fs::read_to_string(precommit_cfg)
            .ok()
            .is_some_and(|content| content.contains("id: vulnera-scan"));

    ctx.output.header("Vulnera Hook Status");
    ctx.output.print(&format!(
        "Git pre-commit hook: {}",
        if git_hook_status {
            "installed"
        } else {
            "not installed"
        }
    ));
    ctx.output.print(&format!(
        "pre-commit config: {}",
        if precommit_status {
            "installed"
        } else {
            "not installed"
        }
    ));

    Ok(exit_codes::SUCCESS)
}

async fn remove_hooks(ctx: &CliContext, args: &RemoveHooksArgs) -> Result<i32> {
    let project_path = resolve_project_path(&ctx.working_dir, &args.path);

    match args.backend {
        HookBackend::Git => {
            let Some(repo_root) = find_git_root(&project_path) else {
                ctx.output.error("Not inside a git repository");
                return Ok(exit_codes::CONFIG_ERROR);
            };

            let hook_path = repo_root.join(".git").join("hooks").join("pre-commit");
            if !hook_path.exists() {
                ctx.output.info("Git pre-commit hook not found");
                return Ok(exit_codes::SUCCESS);
            }

            let existing = std::fs::read_to_string(&hook_path)?;
            let stripped = strip_managed_block(&existing);
            if stripped.trim().is_empty() {
                std::fs::remove_file(&hook_path)?;
            } else {
                std::fs::write(&hook_path, stripped)?;
            }

            ctx.output.success("Removed vulnera git hook block");
        }
        HookBackend::PreCommit => {
            let config_path = project_path.join(".pre-commit-config.yaml");
            if !config_path.exists() {
                ctx.output.info(".pre-commit-config.yaml not found");
                return Ok(exit_codes::SUCCESS);
            }

            let existing = std::fs::read_to_string(&config_path)?;
            let stripped = strip_managed_block(&existing);
            std::fs::write(&config_path, stripped)?;

            ctx.output
                .success("Removed vulnera block from .pre-commit-config.yaml");
        }
    }

    Ok(exit_codes::SUCCESS)
}

fn build_hook_command(args: &InstallHooksArgs) -> String {
    let offline_flag = if args.with_deps { "" } else { " --offline" };
    format!(
        "vulnera analyze . --ci --quiet --changed-only --min-severity {} --fail-on-vuln{}",
        args.min_severity, offline_flag
    )
}

fn strip_managed_block(content: &str) -> String {
    if let (Some(start), Some(end)) = (content.find(HOOK_BEGIN), content.find(HOOK_END)) {
        let end_idx = end + HOOK_END.len();
        let mut output = String::new();
        output.push_str(&content[..start]);
        if end_idx < content.len() {
            output.push_str(&content[end_idx..]);
        }
        output
    } else {
        content.to_string()
    }
}

fn resolve_project_path(working_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        working_dir.join(path)
    }
}

fn find_git_root(path: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("rev-parse")
        .arg("--show-toplevel")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        None
    } else {
        Some(PathBuf::from(root))
    }
}
