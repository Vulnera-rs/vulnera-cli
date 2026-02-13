use std::path::PathBuf;

use anyhow::Result;

use crate::commands::generate_fix::{GenerateFixArgs, GenerateFixResult};
use crate::context::CliContext;
use crate::fix_generator::{CodeFix, FixGenerator};

pub enum GenerateFixExecutionOutcome {
    Success(GenerateFixResult),
    OfflineMode,
    AuthenticationRequired,
    QuotaExceeded,
    MissingFile(PathBuf),
    MissingApiClient,
}

pub struct ExecuteGenerateFixUseCase;

impl ExecuteGenerateFixUseCase {
    pub async fn execute(
        ctx: &mut CliContext,
        args: &GenerateFixArgs,
        offline_mode: bool,
    ) -> Result<GenerateFixExecutionOutcome> {
        if offline_mode {
            return Ok(GenerateFixExecutionOutcome::OfflineMode);
        }

        if !ctx.is_authenticated() {
            return Ok(GenerateFixExecutionOutcome::AuthenticationRequired);
        }

        if ctx.remaining_quota() == 0 {
            return Ok(GenerateFixExecutionOutcome::QuotaExceeded);
        }

        if !ctx.consume_quota().await? {
            return Ok(GenerateFixExecutionOutcome::QuotaExceeded);
        }

        let file_path = if args.code.is_absolute() {
            args.code.clone()
        } else {
            ctx.working_dir.join(&args.code)
        };

        if !file_path.exists() {
            return Ok(GenerateFixExecutionOutcome::MissingFile(file_path));
        }

        let description = args
            .description
            .clone()
            .unwrap_or_else(|| args.vulnerability.clone());

        let client = match ctx.api_client() {
            Some(client) => client.clone(),
            None => return Ok(GenerateFixExecutionOutcome::MissingApiClient),
        };

        let generator = FixGenerator::new(client);
        let fix: Option<CodeFix> = generator
            .generate_fix_with_language(
                &args.vulnerability,
                &description,
                &file_path,
                args.line,
                args.language.as_deref(),
            )
            .await?;

        Ok(GenerateFixExecutionOutcome::Success(GenerateFixResult {
            vulnerability_id: args.vulnerability.clone(),
            file: file_path.to_string_lossy().to_string(),
            line: args.line,
            description,
            fix,
        }))
    }
}
