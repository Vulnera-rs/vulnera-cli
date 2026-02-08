//! Generate Fix Command - AI-powered code fix generation
//!
//! Generates a suggested fix for a vulnerability using the Vulnera LLM endpoint.
//! Requires online mode, authentication, and available quota.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;

use crate::Cli;
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
    if cli.offline {
        ctx.output.error("Generate-fix requires online mode");
        ctx.output
            .info("Remove --offline or configure server access");
        return Ok(exit_codes::NETWORK_ERROR);
    }

    if !ctx.is_authenticated() {
        ctx.output.error("Authentication required for generate-fix");
        ctx.output.info("Run 'vulnera auth login' to authenticate");
        return Ok(exit_codes::AUTH_REQUIRED);
    }

    if ctx.remaining_quota() == 0 {
        ctx.output.error("Quota exceeded");
        ctx.output.info("Run 'vulnera quota status' for details");
        return Ok(exit_codes::QUOTA_EXCEEDED);
    }

    if !ctx.consume_quota().await? {
        ctx.output.error("Quota exceeded");
        return Ok(exit_codes::QUOTA_EXCEEDED);
    }

    let file_path = if args.code.is_absolute() {
        args.code.clone()
    } else {
        ctx.working_dir.join(&args.code)
    };

    if !file_path.exists() {
        ctx.output
            .error(&format!("File does not exist: {:?}", file_path));
        return Ok(exit_codes::CONFIG_ERROR);
    }

    let description = args
        .description
        .clone()
        .unwrap_or_else(|| args.vulnerability.clone());

    let client = match ctx.api_client() {
        Some(client) => client.clone(),
        None => {
            ctx.output
                .error("API client not configured for generate-fix");
            return Ok(exit_codes::NETWORK_ERROR);
        }
    };

    let generator = FixGenerator::new(client);
    let fix = generator
        .generate_fix_with_language(
            &args.vulnerability,
            &description,
            &file_path,
            args.line,
            args.language.as_deref(),
        )
        .await?;

    let result = GenerateFixResult {
        vulnerability_id: args.vulnerability.clone(),
        file: file_path.to_string_lossy().to_string(),
        line: args.line,
        description,
        fix: fix.clone(),
    };

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&result)?;
        }
        OutputFormat::Sarif => {
            print_sarif(&result)?;
        }
        OutputFormat::Table | OutputFormat::Plain => {
            if let Some(fix) = fix {
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
                    "informationUri": "https://github.com/k5602/vulnera"
                }
            },
            "results": [result_obj]
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif)?);
    Ok(())
}
