use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;
use vulnera_core::config::SecretDetectionConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_secrets::module::SecretDetectionModule;

use crate::application::services::scan_targets::resolve_scan_targets;
use crate::commands::secrets::{
    SecretFinding, SecretsArgs, SecretsResult, SecretsSummary, SeverityCounts,
};
use crate::context::CliContext;

pub struct ExecuteSecretsScanUseCase;

impl ExecuteSecretsScanUseCase {
    pub async fn execute(
        ctx: &CliContext,
        args: &SecretsArgs,
        path: &Path,
    ) -> Result<SecretsResult> {
        use crate::file_cache::{CachedFinding, FileCache};

        let mut file_cache = if !args.no_cache {
            FileCache::new(path).ok()
        } else {
            None
        };

        let mut module_cfg = ctx.config.secret_detection.clone();
        apply_secret_overrides(&mut module_cfg, args);
        let secrets_module = SecretDetectionModule::with_config(&module_cfg);

        let scan_targets = resolve_scan_targets(
            path,
            &ctx.working_dir,
            &args.files,
            args.changed_only,
            &args.exclude,
            None,
        )?;

        let mut raw_findings = Vec::new();
        let mut files_scanned = 0usize;

        match scan_targets {
            Some(targets) => {
                for target in targets {
                    let res = execute_target(&secrets_module, &target).await?;
                    files_scanned += res.metadata.files_scanned;
                    raw_findings.extend(res.findings);
                }
            }
            None => {
                let res = execute_target(&secrets_module, path).await?;
                files_scanned += res.metadata.files_scanned;
                raw_findings.extend(res.findings);
            }
        }

        let findings: Vec<SecretFinding> = raw_findings
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
            files_scanned,
            findings,
            summary: SecretsSummary {
                total_findings: by_type.values().sum(),
                by_type,
                by_severity,
                files_scanned,
            },
        })
    }
}

async fn execute_target(
    module: &SecretDetectionModule,
    target: &Path,
) -> Result<vulnera_core::domain::module::ModuleResult> {
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: target.to_string_lossy().to_string(),
        config: Default::default(),
    };

    Ok(module.execute(&module_config).await?)
}

fn apply_secret_overrides(config: &mut SecretDetectionConfig, args: &SecretsArgs) {
    if !args.exclude.is_empty() {
        config.exclude_patterns.extend(args.exclude.clone());
    }

    if !args.include_tests {
        config.exclude_patterns.extend(vec![
            "test".to_string(),
            "tests".to_string(),
            "__tests__".to_string(),
            "spec".to_string(),
        ]);
    }

    config.enable_entropy_detection = args.include_entropy;
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
