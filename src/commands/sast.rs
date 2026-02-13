//! SAST Command - Static Application Security Testing
//!
//! Runs static analysis to find security vulnerabilities in source code.
//! Works fully offline using embedded vulnera-sast module.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
use crate::application::exit_policy;
use crate::application::services::watch_runner;
use crate::application::use_cases::sast::ExecuteSastScanUseCase;
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the sast command
#[derive(Args, Debug)]
pub struct SastArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any vulnerability is found
    #[arg(long)]
    pub fail_on_vuln: bool,

    /// Only analyze changed files (requires git)
    #[arg(long)]
    pub changed_only: bool,

    /// Specific files to analyze
    #[arg(long, value_delimiter = ',')]
    pub files: Vec<PathBuf>,

    /// Exclude paths from analysis (glob patterns)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,

    /// Languages to analyze (auto-detected if not specified)
    #[arg(long, value_delimiter = ',')]
    pub languages: Vec<String>,

    /// Enable specific rule categories
    #[arg(long, value_delimiter = ',')]
    pub rules: Vec<String>,

    /// Disable incremental caching (re-scan all files)
    #[arg(long)]
    pub no_cache: bool,

    /// Watch for file changes and re-scan automatically
    #[arg(long)]
    pub watch: bool,

    /// Generate LLM-powered fix suggestions (requires online mode, SARIF output)
    #[arg(long)]
    pub fix: bool,
}

/// SAST analysis result
#[derive(Debug, Serialize)]
pub struct SastResult {
    pub path: PathBuf,
    pub files_scanned: usize,
    pub languages_detected: Vec<String>,
    pub findings: Vec<SastFinding>,
    pub summary: SastSummary,
}

/// Individual SAST finding
#[derive(Debug, Clone, Serialize)]
pub struct SastFinding {
    pub id: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub message: String,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub snippet: Option<String>,
    pub fix_suggestion: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
}

impl VulnerabilityDisplay for SastFinding {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.rule_id.clone()
    }
    fn package(&self) -> String {
        self.file.clone()
    }
    fn version(&self) -> String {
        format!("L{}", self.line)
    }
    fn description(&self) -> String {
        self.message.clone()
    }
}

/// Summary of SAST results
#[derive(Debug, Serialize)]
pub struct SastSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub files_scanned: usize,
    pub lines_scanned: usize,
}

/// Run the sast command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &SastArgs) -> Result<i32> {
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

/// Run a single SAST scan with cache integration
async fn run_single_scan(
    ctx: &CliContext,
    cli: &Cli,
    args: &SastArgs,
    path: &PathBuf,
) -> Result<i32> {
    let start = std::time::Instant::now();

    if !cli.quiet {
        ctx.output.header("Static Analysis (SAST)");
        ctx.output.info(&format!("Scanning: {:?}", path));
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Scanning source files..."))
    } else {
        None
    };

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match ExecuteSastScanUseCase::execute(ctx, args, path).await {
        Ok(result) => result,
        Err(e) => {
            ctx.output.error(&format!("SAST analysis failed: {}", e));
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
    args: &SastArgs,
    path: &PathBuf,
) -> Result<i32> {
    use crate::watcher::FileWatcher;

    if !cli.quiet {
        ctx.output.header("Static Analysis (SAST) - Watch Mode");
        ctx.output.info(&format!("Watching: {:?}", path));
    }

    // Run initial scan
    let initial_result = run_single_scan(ctx, cli, args, path).await?;
    if initial_result != exit_codes::SUCCESS && args.fail_on_vuln {
        ctx.output.warn("Vulnerabilities found in initial scan");
    }

    // Start file watcher
    let watcher = FileWatcher::new(path, 500)?;

    ctx.output.info("Watching for changes... (Ctrl+C to stop)");

    // Watch loop - blocks until stopped
    watcher.start(|event| {
        println!("\n📝 {} file(s) changed", event.paths.len());

        let scan_result = watch_runner::run_scan(run_single_scan(ctx, cli, args, path));

        match scan_result {
            Ok(code) => {
                if exit_policy::is_findings_exit(code) {
                    println!("⚠ Vulnerabilities detected");
                }
            }
            Err(e) => {
                eprintln!("Scan error: {}", e);
            }
        }

        true // Continue watching
    })?;

    Ok(exit_codes::SUCCESS)
}

/// Output results in the appropriate format
fn output_results(
    ctx: &CliContext,
    cli: &Cli,
    args: &SastArgs,
    result: &SastResult,
    duration: std::time::Duration,
) -> Result<i32> {
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.findings, "vulnera-sast", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No vulnerabilities found in {} files ({:.2}s)",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            } else if !cli.quiet {
                ctx.output.print_findings_table(&result.findings);

                ctx.output.print(&format!(
                    "\nSummary: {} total ({} critical, {} high, {} medium, {} low)",
                    result.summary.total_findings,
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));

                ctx.output.print(&format!(
                    "Scanned {} files in {:.2}s",
                    result.files_scanned,
                    duration.as_secs_f64()
                ));
            }
        }
    }

    // Determine exit code
    Ok(exit_policy::findings_exit_code(
        args.fail_on_vuln,
        !result.findings.is_empty(),
    ))
}
