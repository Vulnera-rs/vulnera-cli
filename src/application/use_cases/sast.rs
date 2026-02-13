use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};
use vulnera_sast::module::SastModule;

use crate::commands::sast::{SastArgs, SastFinding, SastResult, SastSummary};
use crate::context::CliContext;
use crate::severity::{parse_severity, severity_meets_minimum};

pub struct ExecuteSastScanUseCase;

impl ExecuteSastScanUseCase {
    pub async fn execute(
        _ctx: &CliContext,
        args: &SastArgs,
        path: &Path,
    ) -> Result<SastResult> {
        use crate::file_cache::{CachedFinding, FileCache};

        let mut file_cache = if !args.no_cache {
            FileCache::new(path).ok()
        } else {
            None
        };

        let min_severity = parse_severity(&args.min_severity);

        let sast_module = SastModule::new();
        let module_config = ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "cli-local".to_string(),
            source_uri: path.to_string_lossy().to_string(),
            config: Default::default(),
        };

        let res = sast_module.execute(&module_config).await?;

        let findings: Vec<SastFinding> = res
            .findings
            .into_iter()
            .filter(|f| severity_meets_minimum(&f.severity, &min_severity))
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
            files_scanned: res.metadata.files_scanned,
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
            files_scanned: res.metadata.files_scanned,
            languages_detected: Vec::new(),
            findings,
            summary,
        })
    }
}
