//! API Command - API Security Analysis
//!
//! Analyzes API endpoints for security issues.
//! Works fully offline using embedded vulnera-api module.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
use crate::application::exit_policy;
use crate::application::use_cases::api::{ApiExecutionOutcome, ExecuteApiScanUseCase};
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the api command
#[derive(Args, Debug)]
pub struct ApiArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Path to OpenAPI/Swagger specification file
    #[arg(long)]
    pub spec: Option<PathBuf>,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any issue is found
    #[arg(long)]
    pub fail_on_issue: bool,

    /// Framework to analyze (auto-detected if not specified)
    #[arg(long)]
    pub framework: Option<String>,
}

/// API analysis result
#[derive(Debug, Serialize)]
pub struct ApiResult {
    pub path: PathBuf,
    pub spec_file: Option<String>,
    pub framework: Option<String>,
    pub endpoints_found: usize,
    pub findings: Vec<ApiFinding>,
    pub summary: ApiSummary,
}

/// Individual API finding
#[derive(Debug, Clone, Serialize)]
pub struct ApiFinding {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub endpoint: String,
    pub method: String,
    pub issue: String,
    pub description: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub owasp_category: Option<String>,
    pub remediation: String,
}

impl VulnerabilityDisplay for ApiFinding {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.category.clone()
    }
    fn package(&self) -> String {
        format!("{} {}", self.method, self.endpoint)
    }
    fn version(&self) -> String {
        self.file.clone().unwrap_or_default()
    }
    fn description(&self) -> String {
        self.issue.clone()
    }
}

/// Summary of API analysis
#[derive(Debug, Serialize)]
pub struct ApiSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub endpoints_analyzed: usize,
    pub by_category: HashMap<String, usize>,
}

/// Run the api command
pub async fn run(ctx: &CliContext, cli: &Cli, args: &ApiArgs) -> Result<i32> {
    let start = std::time::Instant::now();

    // Resolve path
    let path = if args.path.is_absolute() {
        args.path.clone()
    } else {
        ctx.working_dir.join(&args.path)
    };

    // If spec is provided, use that instead
    let source_path = if let Some(spec) = &args.spec {
        if spec.is_absolute() {
            spec.clone()
        } else {
            ctx.working_dir.join(spec)
        }
    } else {
        path.clone()
    };

    if !source_path.exists() {
        ctx.output
            .error(&format!("Path does not exist: {:?}", source_path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    // API analysis works fully offline
    if !cli.quiet {
        ctx.output.header("API Security Analysis");
        ctx.output.info(&format!("Scanning: {:?}", source_path));
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Analyzing API endpoints..."))
    } else {
        None
    };

    if let Some(p) = &progress {
        p.finish_and_clear();
    }

    let result = match ExecuteApiScanUseCase::execute(args, &source_path).await {
        Ok(ApiExecutionOutcome::Success(result)) => result,
        Ok(ApiExecutionOutcome::NoSpecFound) => {
            if !cli.quiet {
                ctx.output.info("No OpenAPI specification found in directory");
                ctx.output
                    .info("To analyze an API, provide a spec file with --spec");
            }
            return Ok(exit_codes::SUCCESS);
        }
        Err(e) => {
            ctx.output
                .error(&format!("API security analysis failed: {}", e));
            return Ok(exit_codes::INTERNAL_ERROR);
        }
    };

    // Output results
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            ctx.output.sarif(&result.findings, "vulnera-api", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            let duration = start.elapsed();

            if result.findings.is_empty() {
                ctx.output.success(&format!(
                    "No API security issues found ({:.2}s)",
                    duration.as_secs_f64()
                ));

                if let Some(spec) = &result.spec_file {
                    ctx.output.info(&format!("Analyzed spec: {}", spec));
                }
            } else {
                ctx.output.print_findings_table(&result.findings);

                ctx.output.print(&format!(
                    "\nSummary: {} issues ({} critical, {} high, {} medium, {} low)",
                    result.summary.total_findings,
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));

                if !result.summary.by_category.is_empty() {
                    ctx.output.print("\nBy category:");
                    for (category, count) in &result.summary.by_category {
                        ctx.output.print(&format!("  {}: {}", category, count));
                    }
                }

                ctx.output
                    .print(&format!("\nCompleted in {:.2}s", duration.as_secs_f64()));
            }
        }
    }

    // Determine exit code
    Ok(exit_policy::findings_exit_code(
        args.fail_on_issue,
        !result.findings.is_empty(),
    ))
}

