//! Secrets Command - Secret and credential detection
//!
//! Scans for hardcoded secrets, API keys, passwords, and other credentials.
//! Works fully offline using embedded vulnera-secrets module.
//!

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
use crate::application::exit_policy;
use crate::application::services::watch_runner;
use crate::application::use_cases::secrets::ExecuteSecretsScanUseCase;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the secrets command
#[derive(Args, Debug)]
pub struct SecretsArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Fail if any secret is found
    #[arg(long)]
    pub fail_on_secret: bool,

    /// Only analyze changed files (requires git)
    #[arg(long)]
    pub changed_only: bool,

    /// Specific files to analyze
    #[arg(long, value_delimiter = ',')]
    pub files: Vec<PathBuf>,

    /// Exclude paths from analysis (glob patterns)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Include patterns that are usually excluded (e.g., test files)
    #[arg(long)]
    pub include_tests: bool,

    /// Show entropy-based detections (more false positives)
    #[arg(long)]
    pub include_entropy: bool,

    /// Disable incremental caching (re-scan all files)
    #[arg(long)]
    pub no_cache: bool,

    /// Watch for file changes and re-scan automatically
    #[arg(long)]
    pub watch: bool,
}

/// Secrets detection result
#[derive(Debug, Serialize)]
pub struct SecretsResult {
    pub path: PathBuf,
    pub files_scanned: usize,
    pub findings: Vec<SecretFinding>,
    pub summary: SecretsSummary,
}

/// Individual secret finding
#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub id: String,
    pub secret_type: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub match_text: String,
    pub redacted_value: String,
    pub description: String,
    pub remediation: String,
}

impl VulnerabilityDisplay for SecretFinding {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.secret_type.clone()
    }
    fn package(&self) -> String {
        self.file.clone()
    }
    fn version(&self) -> String {
        format!("L{}", self.line)
    }
    fn description(&self) -> String {
        format!("{}: {}", self.secret_type, self.redacted_value)
    }
}

/// Summary of secrets detection
#[derive(Debug, Serialize)]
pub struct SecretsSummary {
    pub total_findings: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: SeverityCounts,
    pub files_scanned: usize,
}

/// Severity breakdown
#[derive(Debug, Serialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

/// Run the secrets command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &SecretsArgs) -> Result<i32> {
    let path = if args.path.is_absolute() {
        args.path.clone()
    } else {
        ctx.working_dir.join(&args.path)
    };

    if !path.exists() {
        ctx.output
            .error(&format!("Path does not exist: {:?}", path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // Handle watch mode
    if args.watch {
        return run_watch_mode(ctx, cli, args, &path).await;
    }

    // Single scan
    run_single_scan(ctx, cli, args, &path).await
}

/// Run a single secrets scan with cache integration
async fn run_single_scan(
    ctx: &CliContext,
    cli: &Cli,
    args: &SecretsArgs,
    path: &PathBuf,
) -> Result<i32> {
    let start = std::time::Instant::now();

    if !cli.quiet {
        ctx.output.header("Secret Detection");
        ctx.output.info(&format!("Scanning: {:?}", path));
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Scanning for secrets..."))
    } else {
        None
    };

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match ExecuteSecretsScanUseCase::execute(ctx, args, path).await {
        Ok(result) => result,
        Err(e) => {
            ctx.output.error(&format!("Secret detection failed: {}", e));
            return Ok(exit_codes::INTERNAL_ERROR);
        }
    };

    // Output results
    output_results(ctx, cli, args, &result, start.elapsed())
}

/// Run watch mode - continuously monitor for file changes
async fn run_watch_mode(
    ctx: &CliContext,
    cli: &Cli,
    args: &SecretsArgs,
    path: &PathBuf,
) -> Result<i32> {
    use crate::watcher::FileWatcher;

    if !cli.quiet {
        ctx.output.header("Secret Detection - Watch Mode");
        ctx.output.info(&format!("Watching: {:?}", path));
    }

    // Run initial scan
    let initial_result = run_single_scan(ctx, cli, args, path).await?;
    if initial_result != exit_codes::SUCCESS && args.fail_on_secret {
        ctx.output.warn("Secrets found in initial scan");
    }

    // Start file watcher
    let watcher = FileWatcher::new(path, 500)?;

    ctx.output.info("Watching for changes... (Ctrl+C to stop)");

    // Watch loop
    watcher.start(|event| {
        println!("\n📝 {} file(s) changed", event.paths.len());

        let scan_result = watch_runner::run_scan(run_single_scan(ctx, cli, args, path));

        match scan_result {
            Ok(code) => {
                if exit_policy::is_findings_exit(code) {
                    println!("⚠ Secrets detected");
                }
            }
            Err(e) => {
                eprintln!("Scan error: {}", e);
            }
        }

        true
    })?;

    Ok(exit_codes::SUCCESS)
}

/// Output results in the appropriate format
fn output_results(
    ctx: &CliContext,
    cli: &Cli,
    args: &SecretsArgs,
    result: &SecretsResult,
    duration: std::time::Duration,
) -> Result<i32> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.findings, "vulnera-secrets", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No secrets found in {} files ({:.2}s)",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            } else if !cli.quiet {
                ctx.output.print_findings_table(&result.findings);

                ctx.output.print(&format!(
                    "\nSummary: {} secrets found ({} critical, {} high, {} medium, {} low)",
                    result.summary.total_findings,
                    result.summary.by_severity.critical,
                    result.summary.by_severity.high,
                    result.summary.by_severity.medium,
                    result.summary.by_severity.low
                ));

                if !result.summary.by_type.is_empty() {
                    ctx.output.print("\nBy type:");
                    for (secret_type, count) in &result.summary.by_type {
                        ctx.output.print(&format!("  {}: {}", secret_type, count));
                    }
                }

                ctx.output.print(&format!(
                    "\nScanned {} files in {:.2}s",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));

                ctx.output.warn(
                    "⚠ IMPORTANT: Rotate all detected credentials immediately. \
                     Secrets may have been exposed in version control history.",
                );
            }
        }
    }

    // Determine exit code
    Ok(exit_policy::findings_exit_code(
        args.fail_on_secret,
        !result.findings.is_empty(),
    ))
}

