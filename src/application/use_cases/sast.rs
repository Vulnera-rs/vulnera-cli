use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;
use vulnera_core::config::SastConfig;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::module::SastModule;

use crate::application::services::scan_targets::resolve_scan_targets;
use crate::commands::sast::{SastArgs, SastFinding, SastResult, SastSummary};
use crate::context::CliContext;
use crate::severity::{parse_severity, severity_meets_minimum};

pub struct ExecuteSastScanUseCase;

impl ExecuteSastScanUseCase {
    pub async fn execute(ctx: &CliContext, args: &SastArgs, path: &Path) -> Result<SastResult> {
        use crate::file_cache::{CachedFinding, FileCache};

        let mut file_cache = if !args.no_cache {
            FileCache::new(path).ok()
        } else {
            None
        };

        let min_severity = parse_severity(&args.min_severity);

        let mut module_cfg = ctx.config.sast.clone();
        apply_sast_overrides(&mut module_cfg, args);
        let sast_module = SastModule::with_config(&module_cfg);

        let scan_targets = resolve_scan_targets(
            path,
            &ctx.working_dir,
            &args.files,
            args.changed_only,
            &args.exclude,
            Some(&args.languages),
        )?;

        let mut raw_findings = Vec::new();
        let mut files_scanned = 0usize;

        match scan_targets {
            Some(targets) => {
                for target in targets {
                    let res = execute_target(&sast_module, &target).await?;
                    files_scanned += res.metadata.files_scanned;
                    raw_findings.extend(res.findings);
                }
            }
            None => {
                let res = execute_target(&sast_module, path).await?;
                files_scanned += res.metadata.files_scanned;
                raw_findings.extend(res.findings);
            }
        }

        let findings: Vec<SastFinding> = raw_findings
            .into_iter()
            .filter(|f| severity_meets_minimum(&f.severity, &min_severity))
            .filter(|f| matches_rule_filter(f.rule_id.as_deref(), &args.rules))
            .map(|f| SastFinding {
                id: f.id,
                rule_id: f.rule_id.unwrap_or_else(|| "unknown".to_string()),
                severity: format!("{:?}", f.severity).to_lowercase(),
                category: "SAST".to_string(),
                message: f.description.clone(),
                file: f.location.path.clone(),
                line: f.location.line.unwrap_or(0),
                column: f.location.column,
                end_line: f.location.end_line,
                snippet: None,
                fix_suggestion: f.recommendation,
                cwe: None,
                owasp: None,
            })
            .collect();

        if let Some(ref mut cache) = file_cache {
            let mut findings_by_file: HashMap<String, Vec<CachedFinding>> = HashMap::new();

            for finding in &findings {
                let cached = CachedFinding {
                    id: finding.id.clone(),
                    rule_id: Some(finding.rule_id.clone()),
                    severity: finding.severity.clone(),
                    description: finding.message.clone(),
                    line: Some(finding.line),
                    column: finding.column,
                    module: "sast".to_string(),
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

        let mut summary = SastSummary {
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            files_scanned,
            lines_scanned: 0,
        };

        for finding in &findings {
            match finding.severity.as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                _ => {}
            }
        }

        Ok(SastResult {
            path: path.to_path_buf(),
            files_scanned,
            languages_detected: args.languages.clone(),
            findings,
            summary,
        })
    }
}

async fn execute_target(sast_module: &SastModule, target: &Path) -> Result<vulnera_core::domain::module::ModuleResult> {
    let module_config = ModuleConfig {
        job_id: Uuid::new_v4(),
        project_id: "cli-local".to_string(),
        source_uri: target.to_string_lossy().to_string(),
        config: Default::default(),
    };

    Ok(sast_module.execute(&module_config).await?)
}

fn apply_sast_overrides(config: &mut SastConfig, args: &SastArgs) {
    if !args.exclude.is_empty() {
        config.exclude_patterns.extend(args.exclude.clone());
    }

    if args.no_cache {
        config.enable_incremental = Some(false);
    } else if args.changed_only {
        config.enable_incremental = Some(true);
    }
}

fn matches_rule_filter(rule_id: Option<&str>, rules: &[String]) -> bool {
    if rules.is_empty() {
        return true;
    }

    let Some(rule_id) = rule_id else {
        return false;
    };

    let normalized_rule = rule_id.to_ascii_lowercase();
    rules.iter().any(|needle| {
        let normalized = needle.trim().to_ascii_lowercase();
        !normalized.is_empty()
            && (normalized_rule == normalized || normalized_rule.contains(&normalized))
    })
}
