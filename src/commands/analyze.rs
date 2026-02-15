//! Analyze Command - Full vulnerability analysis
//!
//! Runs comprehensive vulnerability analysis including:
//! - Static analysis (SAST) - offline
//! - Secret detection - offline
//! - API security analysis - offline
//! - Dependency vulnerability scanning - requires server
//!
//! In offline mode, runs all offline modules and skips deps with a warning.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
use crate::application::exit_policy;
use crate::application::use_cases::analyze::{DepsRunStatus, ExecuteAnalyzeUseCase};
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::{OutputFormat, ProgressIndicator, VulnerabilityDisplay};

/// Arguments for the analyze command
#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// Path to the project directory (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Skip dependency vulnerability scanning
    #[arg(long)]
    pub skip_deps: bool,

    /// Skip static analysis (SAST)
    #[arg(long)]
    pub skip_sast: bool,

    /// Skip secret detection
    #[arg(long)]
    pub skip_secrets: bool,

    /// Skip API security analysis
    #[arg(long)]
    pub skip_api: bool,

    /// Minimum severity to report (critical, high, medium, low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Fail if any vulnerability is found (useful for CI)
    #[arg(long)]
    pub fail_on_vuln: bool,

    /// Only analyze changed files (requires git)
    #[arg(long)]
    pub changed_only: bool,

    /// Exclude paths from analysis (glob patterns)
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,
}

/// Analysis result summary
#[derive(Debug, Serialize)]
pub struct AnalysisResult {
    pub path: PathBuf,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub summary: AnalysisSummary,
    pub modules_run: Vec<String>,
    pub warnings: Vec<String>,
}

/// Individual vulnerability information
#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub severity: String,
    pub package: String,
    pub version: String,
    pub description: String,
    pub module: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub fix_available: bool,
    pub fixed_version: Option<String>,
}

impl VulnerabilityDisplay for VulnerabilityInfo {
    fn severity(&self) -> String {
        self.severity.clone()
    }
    fn id(&self) -> String {
        self.id.clone()
    }
    fn package(&self) -> String {
        self.package.clone()
    }
    fn version(&self) -> String {
        self.version.clone()
    }
    fn description(&self) -> String {
        self.description.clone()
    }
}

/// Summary of analysis results
#[derive(Debug, Serialize)]
pub struct AnalysisSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub files_scanned: usize,
    pub duration_ms: u64,
}

/// Run the analyze command
pub async fn run(ctx: &mut CliContext, cli: &Cli, args: &AnalyzeArgs) -> Result<i32> {
    let start = std::time::Instant::now();

    // Resolve path
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

    // Show analysis start
    if !cli.quiet {
        ctx.output.banner();
        ctx.output.info(&format!("Analyzing: {:?}", path));

        if cli.offline {
            ctx.output
                .warn("Running in offline mode - dependency analysis will be skipped");
        }
    }

    // Create progress indicator
    let progress = if !cli.quiet && !cli.ci {
        Some(ProgressIndicator::spinner("Initializing analysis..."))
    } else {
        None
    };

    if let Some(p) = &progress {
        p.set_message("Running analysis modules...");
    }

    let execution = ExecuteAnalyzeUseCase::execute(ctx, args, &path, cli.offline).await;
    let mut result = execution.result;
    let quota_exceeded = execution.deps_status == DepsRunStatus::QuotaExceeded;

    if cli.offline && !args.skip_deps && !cli.quiet {
        ctx.output
            .warn("Dependency analysis skipped (requires server connection)");
    }

    if let Some(p) = progress {
        p.finish_and_clear();
    }

    // Calculate summary
    let duration = start.elapsed();
    result.summary.duration_ms = duration.as_millis() as u64;
    result.summary.total = result.vulnerabilities.len();

    for vuln in &result.vulnerabilities {
        match vuln.severity.to_lowercase().as_str() {
            "critical" => result.summary.critical += 1,
            "high" => result.summary.high += 1,
            "medium" => result.summary.medium += 1,
            "low" => result.summary.low += 1,
            _ => {}
        }
    }

    // Output results
    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            ctx.output
                .sarif(&result.vulnerabilities, "vulnera", "1.0.0")?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if result.vulnerabilities.is_empty() {
                ctx.output.success(&format!(
                    "No vulnerabilities found ({:.2}s)",
                    duration.as_secs_f64()
                ));
            } else {
                ctx.output.print_findings_table(&result.vulnerabilities);

                ctx.output.print(&format!(
                    "\nSummary: {} total ({} critical, {} high, {} medium, {} low)",
                    result.summary.total,
                    result.summary.critical,
                    result.summary.high,
                    result.summary.medium,
                    result.summary.low
                ));
            }

            // Show modules run with styling
            ctx.output.divider();
            ctx.output
                .print(&format!("Modules: {}", result.modules_run.join(", ")));

            // Show warnings
            for warning in &result.warnings {
                ctx.output.warn(warning);
            }

            ctx.output
                .print(&format!("✓ Completed in {:.2}s", duration.as_secs_f64()));
            ctx.output.divider();
        }
    }

    // Determine exit code
    Ok(exit_policy::analyze_exit_code(
        quota_exceeded,
        args.fail_on_vuln,
        !result.vulnerabilities.is_empty(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::{
        FindingSeverity, parse_severity, severity_meets_minimum, severity_meets_minimum_str,
    };

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), FindingSeverity::Critical);
        assert_eq!(parse_severity("high"), FindingSeverity::High);
        assert_eq!(parse_severity("medium"), FindingSeverity::Medium);
        assert_eq!(parse_severity("low"), FindingSeverity::Low);
        assert_eq!(parse_severity("info"), FindingSeverity::Info); // Info is preserved
        assert_eq!(parse_severity("unknown"), FindingSeverity::Low); // Default fallback
        assert_eq!(parse_severity("CRITICAL"), FindingSeverity::Critical); // Case insensitive
    }

    #[test]
    fn test_severity_meets_minimuma_str() {
        assert!(severity_meets_minimum_str("critical", "high"));
        assert!(!severity_meets_minimum_str("high", "critical"));
    }

    #[test]
    fn test_severity_meets_minimum() {
        // Critical meets everything
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Critical
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Critical,
            &FindingSeverity::Low
        ));

        // High meets High and Low, but not Critical
        assert!(!severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::Critical
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::High,
            &FindingSeverity::Low
        ));

        // Low meets Low, but not High or Critical
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Critical
        ));
        assert!(!severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::High
        ));
        assert!(severity_meets_minimum(
            &FindingSeverity::Low,
            &FindingSeverity::Low
        ));
    }

    #[test]
    fn test_severity_meets_minimum_str() {
        assert!(severity_meets_minimum_str("critical", "high"));
        assert!(severity_meets_minimum_str("high", "high"));
        assert!(!severity_meets_minimum_str("medium", "high"));
        assert!(!severity_meets_minimum_str("low", "high"));
    }

    #[test]
    fn test_vulnerability_display() {
        let vuln = VulnerabilityInfo {
            id: "TEST-001".to_string(),
            severity: "high".to_string(),
            package: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: "Test description".to_string(),
            module: "test".to_string(),
            file: Some("test.rs".to_string()),
            line: Some(10),
            fix_available: true,
            fixed_version: Some("1.0.1".to_string()),
        };

        assert_eq!(vuln.id(), "TEST-001");
        assert_eq!(vuln.severity(), "high");
        assert_eq!(vuln.package(), "test-pkg");
        assert_eq!(vuln.version(), "1.0.0");
        assert_eq!(vuln.description(), "Test description");
    }
}
