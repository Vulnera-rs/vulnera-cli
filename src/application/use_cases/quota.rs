use anyhow::{Result, anyhow};

use crate::api_client::QuotaStatusResponse;
use crate::context::CliContext;

pub enum QuotaServerStatus {
    Connected(QuotaStatusResponse),
    Unreachable,
    Offline,
}

pub struct ShowQuotaOutcome {
    pub status: crate::quota_tracker::QuotaStatus,
    pub server_status: QuotaServerStatus,
}

pub struct SyncQuotaOutcome {
    pub used: u32,
    pub limit: u32,
}

pub struct ShowQuotaUseCase;

impl ShowQuotaUseCase {
    pub async fn execute(ctx: &CliContext, offline: bool) -> Result<ShowQuotaOutcome> {
        let status = ctx.quota.status();

        let server_status = if offline {
            QuotaServerStatus::Offline
        } else {
            match ctx.create_api_client() {
                Ok(client) => match client.get_quota().await {
                    Ok(server_quota) => QuotaServerStatus::Connected(server_quota),
                    Err(_) => QuotaServerStatus::Unreachable,
                },
                Err(_) => QuotaServerStatus::Unreachable,
            }
        };

        Ok(ShowQuotaOutcome {
            status,
            server_status,
        })
    }
}

pub struct SyncQuotaUseCase;

impl SyncQuotaUseCase {
    pub async fn execute(ctx: &mut CliContext, offline: bool) -> Result<SyncQuotaOutcome> {
        if offline {
            return Err(anyhow!("Cannot sync quota in offline mode"));
        }

        let client = ctx.create_api_client()?;
        let server_quota = client.get_quota().await?;

        ctx.quota
            .apply_server_quota(server_quota.used, server_quota.limit)?;

        Ok(SyncQuotaOutcome {
            used: server_quota.used,
            limit: server_quota.limit,
        })
    }
}
