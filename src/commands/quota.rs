//! Quota Command - View and manage usage quota
//!
//! Shows remaining daily quota and sync status.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::Cli;
use crate::application::use_cases::quota::{
    QuotaServerStatus, ShowQuotaUseCase, SyncQuotaUseCase,
};
use crate::context::CliContext;
use crate::exit_codes;
use crate::output::OutputFormat;

/// Arguments for the quota command
#[derive(Args, Debug)]
pub struct QuotaArgs {
    #[command(subcommand)]
    pub command: Option<QuotaCommand>,
}

#[derive(Subcommand, Debug, Clone, Copy)]
pub enum QuotaCommand {
    /// Show current quota status (default)
    Show,
    /// Sync quota with remote server
    Sync,
    /// Reset local quota (for debugging)
    #[command(hide = true)]
    Reset,
}

/// Quota information for JSON output
#[derive(Debug, Serialize)]
pub struct QuotaInfo {
    pub used: u32,
    pub limit: u32,
    pub remaining: u32,
    pub reset_hours: i64,
    pub reset_minutes: i64,
    pub is_authenticated: bool,
    pub last_sync: Option<String>,
}

/// Run the quota command
pub async fn run(ctx: &mut CliContext, cli: &Cli, args: &QuotaArgs) -> Result<i32> {
    let command = args.command.unwrap_or(QuotaCommand::Show);

    match command {
        QuotaCommand::Show => show_quota(ctx, cli).await,
        QuotaCommand::Sync => sync_quota(ctx, cli).await,
        QuotaCommand::Reset => reset_quota(ctx, cli).await,
    }
}

/// Show current quota status
async fn show_quota(ctx: &CliContext, cli: &Cli) -> Result<i32> {
    let outcome = ShowQuotaUseCase::execute(ctx, cli.offline).await?;
    let status = outcome.status;

    let info = QuotaInfo {
        used: status.used,
        limit: status.limit,
        remaining: status.remaining,
        reset_hours: status.reset_time.num_hours(),
        reset_minutes: status.reset_time.num_minutes() % 60,
        is_authenticated: status.is_authenticated,
        last_sync: status.last_sync.map(|t| t.to_rfc3339()),
    };

    match ctx.output.format() {
        OutputFormat::Json => {
            ctx.output.json(&info)?;
        }
        OutputFormat::Table | OutputFormat::Plain | OutputFormat::Sarif => {
            ctx.output.header("Quota Status");

            // Progress bar style display
            let bar_width = 30;
            let filled = ((status.used as f64 / status.limit as f64) * bar_width as f64) as usize;
            let empty = bar_width - filled;
            let bar = format!(
                "[{}{}] {}/{}",
                "█".repeat(filled),
                "░".repeat(empty),
                status.used,
                status.limit
            );

            ctx.output.print(&format!("Usage: {}", bar));
            ctx.output
                .print(&format!("Remaining: {} requests", status.remaining));
            ctx.output.print(&format!(
                "Resets in: {}h {}m (UTC midnight)",
                info.reset_hours, info.reset_minutes
            ));

            if status.is_authenticated {
                ctx.output.print("Account: Authenticated (40 requests/day)");
            } else {
                ctx.output
                    .print("Account: Unauthenticated (10 requests/day)");
                ctx.output
                    .info("Tip: Run 'vulnera auth login' for 40 requests/day");
            }

            if let Some(sync_time) = &status.last_sync {
                ctx.output.print(&format!("Last sync: {}", sync_time));
            }

            match outcome.server_status {
                QuotaServerStatus::Connected(server_quota) => {
                    ctx.output.success("Connected to Vulnera server");
                    if server_quota.used != status.used {
                        ctx.output.warn(&format!(
                            "Server shows {}/{} used - run 'vulnera quota sync' to update",
                            server_quota.used, server_quota.limit
                        ));
                    }
                }
                QuotaServerStatus::Unreachable => {
                    if !cli.offline {
                        ctx.output.warn("Could not fetch server quota");
                    }
                }
                QuotaServerStatus::Offline => {}
            }
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Sync quota with remote server
async fn sync_quota(ctx: &mut CliContext, cli: &Cli) -> Result<i32> {
    ctx.output.info("Syncing quota with server...");

    match SyncQuotaUseCase::execute(ctx, cli.offline).await {
        Ok(outcome) => {
            ctx.output.success("Quota synced successfully");
            ctx.output.print(&format!(
                "Server quota: {}/{} ({} remaining)",
                outcome.used,
                outcome.limit,
                outcome.limit - outcome.used
            ));
        }
        Err(e) => {
            let error_text = e.to_string();
            if error_text.contains("offline mode") {
                ctx.output.error("Cannot sync quota in offline mode");
            } else {
                ctx.output.error(&format!("Failed to sync quota: {}", error_text));
            }
            return Ok(exit_codes::NETWORK_ERROR);
        }
    }

    Ok(exit_codes::SUCCESS)
}

/// Reset local quota (hidden command for debugging)
async fn reset_quota(ctx: &mut CliContext, cli: &Cli) -> Result<i32> {
    // Confirm in interactive mode
    if !cli.ci {
        let confirm = crate::output::confirm(
            "Reset local quota to 0? (This is for debugging only)",
            false,
            cli.ci,
        )?;
        if !confirm {
            ctx.output.info("Reset cancelled");
            return Ok(exit_codes::SUCCESS);
        }
    }

    if let Err(e) = ctx.quota.reset() {
        ctx.output
            .error(&format!("Failed to reset local quota: {}", e));
        return Ok(exit_codes::INTERNAL_ERROR);
    }

    ctx.output.warn("Local quota reset (debug command)");
    ctx.output
        .info("Note: This does not affect server-side quota tracking");

    Ok(exit_codes::SUCCESS)
}
