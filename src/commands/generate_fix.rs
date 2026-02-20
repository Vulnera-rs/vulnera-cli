//! Generate Fix Command - AI-powered code fix generation
//!
//! Generates a suggested fix for a vulnerability using the Vulnera LLM endpoint.
//! Requires online mode, authentication, and available quota.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
use crate::application::use_cases::generate_fix::{
    ExecuteGenerateFixUseCase, GenerateFixExecutionOutcome,
};
use crate::context::CliContext;
use crate::exit_codes;
use crate::fix_generator::{CodeFix, FixGenerator};
use crate::output::OutputFormat;

/// Arguments for the generate-fix command
#[derive(Args, Debug)]
pub struct GenerateFixArgs {
    /// Vulnerability ID (e.g., CVE-2024-1234)
    #[arg(long, value_name = "ID")]
    pub vulnerability: String,

    /// Path to the vulnerable code file
    #[arg(long, value_name = "PATH")]
    pub code: PathBuf,

    /// Line number of the vulnerable code
    #[arg(long, value_name = "LINE")]
    pub line: u32,

    /// Description of the vulnerability (used to improve fix quality)
    #[arg(long, value_name = "TEXT")]
    pub description: Option<String>,

    /// Override language (auto-detected if omitted)
    #[arg(long, value_name = "LANG")]
    pub language: Option<String>,
}

/// Response for JSON output
#[derive(Debug, Serialize)]
pub struct GenerateFixResult {
    pub vulnerability_id: String,
    pub file: String,
    pub line: u32,
    pub description: String,
    pub fix: Option<CodeFix>,
}

/// Run the generate-fix command
pub async fn run(ctx: &mut CliContext, cli: &Cli, args: &GenerateFixArgs) -> Result<i32> {
    let result = match ExecuteGenerateFixUseCase::execute(ctx, args, cli.offline).await? {
        GenerateFixExecutionOutcome::Success(result) => result,
        GenerateFixExecutionOutcome::OfflineMode => {
            ctx.output.error("Generate-fix requires online mode");
            ctx.output
                .info("Remove --offline or configure server access");
            return Ok(exit_codes::NETWORK_ERROR);
        }
        GenerateFixExecutionOutcome::AuthenticationRequired => {
            ctx.output.error("Authentication required for generate-fix");
            ctx.output.info("Run 'vulnera auth login' to authenticate");
            return Ok(exit_codes::AUTH_REQUIRED);
        }
        GenerateFixExecutionOutcome::QuotaExceeded => {
            ctx.output.error("Quota exceeded");
            ctx.output.info("Run 'vulnera quota status' for details");
            return Ok(exit_codes::QUOTA_EXCEEDED);
        }
        GenerateFixExecutionOutcome::MissingFile(file_path) => {
            ctx.output
                .error(&format!("File does not exist: {:?}", file_path));
            return Ok(exit_codes::CONFIG_ERROR);
        }
        GenerateFixExecutionOutcome::MissingApiClient => {
            ctx.output
                .error("API client not configured for generate-fix");
            return Ok(exit_codes::NETWORK_ERROR);
        }
    };

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            print_sarif(&result)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if let Some(fix) = result.fix.clone() {
                ctx.output.success("Fix generated");
                ctx.output
                    .print(&format!("Vulnerability: {}", result.vulnerability_id));
                ctx.output.print(&format!("File: {}", result.file));
                ctx.output.print(&format!("Line: {}", result.line));
                ctx.output
                    .print(&format!("Explanation: {}", fix.explanation));
                ctx.output.print("\nSuggested Fix:\n");
                ctx.output.print(&fix.suggested_code);
            } else {
                ctx.output.warn("No fix was generated");
                ctx.output
                    .info("Try providing a more detailed description or accurate line number");
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

fn print_sarif(result: &GenerateFixResult) -> Result<()> {
    use serde_json::json;

    let fix = result
        .fix
        .as_ref()
        .map(|f| FixGenerator::to_sarif_fix(f, &result.file, result.line));

    let mut result_obj = json!({
        "ruleId": result.vulnerability_id,
        "level": "error",
        "message": {
            "text": result.description
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": result.file
                },
                "region": {
                    "startLine": result.line
                }
            }
        }]
    });

    if let Some(f) = fix {
        result_obj["fixes"] = json!([f]);
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vulnera",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/Vulnera-rs/vulnera"
                }
            },
            "results": [result_obj]
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}
