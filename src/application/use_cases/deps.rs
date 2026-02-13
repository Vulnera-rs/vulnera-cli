use std::path::Path;

use anyhow::{Result, anyhow};

use crate::api_client::SimpleDepsResponse;
use crate::context::CliContext;

pub struct ExecuteDepsScanUseCase;

impl ExecuteDepsScanUseCase {
    pub async fn execute(
        ctx: &mut CliContext,
        path: &Path,
        package_manager: Option<&str>,
        include_transitive: bool,
    ) -> Result<SimpleDepsResponse> {
        if ctx.offline_mode {
            return Err(anyhow!("Dependency analysis requires server connection"));
        }

        if ctx.remaining_quota() == 0 {
            return Err(anyhow!("Quota exceeded"));
        }

        if !ctx.consume_quota().await? {
            return Err(anyhow!("Quota exceeded"));
        }

        let client = ctx.create_api_client()?;
        let response = client
            .analyze_dependencies(path, package_manager, include_transitive)
            .await?;

        Ok(response)
    }
}
