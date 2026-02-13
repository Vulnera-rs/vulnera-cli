use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_secrets::module::SecretDetectionModule;

use crate::commands::secrets::{SecretFinding, SecretsArgs, SecretsResult, SecretsSummary, SeverityCounts};
use crate::context::CliContext;

pub struct ExecuteSecretsScanUseCase;

impl ExecuteSecretsScanUseCase {
    pub async fn execute(
        _ctx: &CliContext,
        args: &SecretsArgs,
        path: &Path,
    ) -> Result<SecretsResult> {
        use crate::file_cache::{CachedFinding, FileCache};

        let mut file_cache = if !args.no_cache {
            FileCache::new(path).ok()
        } else {
            None
        };

        let secrets_module = SecretDetectionModule::new();
        let module_config = ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "cli-local".to_string(),
            source_uri: path.to_string_lossy().to_string(),
            config: Default::default(),
        };

        let res = secrets_module.execute(&module_config).await?;

        let findings: Vec<SecretFinding> = res
            .findings
            .into_iter()
            .map(|f| SecretFinding {
                id: f.id,
                secret_type: f.rule_id.unwrap_or_else(|| "unknown".to_string()),
                severity: format!("{:?}", f.severity).to_lowercase(),
                file: f.location.path.clone(),
                line: f.location.line.unwrap_or(0),
                column: f.location.column,
                match_text: String::new(),
                redacted_value: redact_secret(&f.description),
                description: f.description,
                remediation: f.recommendation.unwrap_or_else(|| {
                    "Remove the secret and rotate credentials immediately".to_string()
                }),
            })
            .collect();

        if let Some(ref mut cache) = file_cache {
            let mut findings_by_file: HashMap<String, Vec<CachedFinding>> = HashMap::new();

            for finding in &findings {
                let cached = CachedFinding {
                    id: finding.id.clone(),
                    rule_id: Some(finding.secret_type.clone()),
                    severity: finding.severity.clone(),
                    description: finding.description.clone(),
                    line: Some(finding.line),
                    column: finding.column,
                    module: "secrets".to_string(),
                };
                findings_by_file
                    .entry(finding.file.clone())
                    .or_default()
                    .push(cached);
            }

            for (file, file_findings) in findings_by_file {
                let file_path = std::path::Path::new(&file);
                if file_path.exists() {
                    let _ = cache.update_file(file_path, file_findings);
                }
            }

            let _ = cache.save();
        }

        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_severity = SeverityCounts {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        for finding in &findings {
            *by_type.entry(finding.secret_type.clone()).or_insert(0) += 1;
            match finding.severity.as_str() {
                "critical" => by_severity.critical += 1,
                "high" => by_severity.high += 1,
                "medium" => by_severity.medium += 1,
                "low" => by_severity.low += 1,
                _ => {}
            }
        }

        Ok(SecretsResult {
            path: path.to_path_buf(),
            files_scanned: res.metadata.files_scanned,
            findings,
            summary: SecretsSummary {
                total_findings: by_type.values().sum(),
                by_type,
                by_severity,
                files_scanned: res.metadata.files_scanned,
            },
        })
    }
}

fn redact_secret(description: &str) -> String {
    if description.len() > 20 {
        let prefix = &description[..8];
        let suffix = &description[description.len() - 4..];
        format!("{}...{}", prefix, suffix)
    } else if description.len() > 8 {
        format!("{}...", &description[..4])
    } else {
        "[REDACTED]".to_string()
    }
}
