use anyhow::Result;

use crate::context::CliContext;

pub enum LoginVerificationStatus {
    Verified,
    Invalid,
    Unreachable(String),
    SkippedOffline,
}

pub struct LoginOutcome {
    pub storage_method: String,
    pub verification: LoginVerificationStatus,
}

pub struct AuthStatusOutcome {
    pub authenticated: bool,
    pub storage_method: String,
    pub server_url: String,
    pub quota_limit: u32,
    pub server_connected: Option<bool>,
}

pub struct LoginUseCase;

impl LoginUseCase {
    pub async fn execute(
        ctx: &CliContext,
        offline: bool,
        server_url: String,
        api_key: String,
    ) -> Result<LoginOutcome> {
        ctx.credentials.store_api_key(&api_key)?;

        let verification = if offline {
            LoginVerificationStatus::SkippedOffline
        } else {
            let client = ctx.create_api_client_for_server(&server_url, Some(api_key))?;
            match client.verify_api_key().await {
                Ok(true) => LoginVerificationStatus::Verified,
                Ok(false) => LoginVerificationStatus::Invalid,
                Err(e) => LoginVerificationStatus::Unreachable(e.to_string()),
            }
        };

        Ok(LoginOutcome {
            storage_method: ctx.credentials.storage_method().to_string(),
            verification,
        })
    }
}

pub struct LogoutUseCase;

impl LogoutUseCase {
    pub fn execute(ctx: &CliContext) -> Result<()> {
        ctx.credentials.delete_api_key()?;
        Ok(())
    }
}

pub struct StatusUseCase;

impl StatusUseCase {
    pub async fn execute(ctx: &CliContext, offline: bool) -> Result<AuthStatusOutcome> {
        let authenticated = ctx.credentials.has_credentials();
        let quota_limit = if authenticated { 40 } else { 10 };

        let server_connected = if offline {
            None
        } else {
            let api_key = ctx.credentials.get_api_key().ok().flatten();
            let client = ctx.create_api_client_for_server(&ctx.server_url, api_key)?;
            match client.health_check().await {
                Ok(ok) => Some(ok),
                Err(_) => Some(false),
            }
        };

        Ok(AuthStatusOutcome {
            authenticated,
            storage_method: ctx.credentials.storage_method().to_string(),
            server_url: ctx.server_url.clone(),
            quota_limit,
            server_connected,
        })
    }
}
