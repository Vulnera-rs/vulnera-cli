use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::commands::sast::{
    SastDepsSuggestion, SastFixReport, SastFixSuggestion, SastGeneratedFix, SastFinding,
};
use crate::context::CliContext;
use crate::fix_generator::FixGenerator;

pub enum SastFixExecutionOutcome {
    Success(SastFixReport),
    OfflineMode(SastFixReport),
    AuthenticationRequired(SastFixReport),
    QuotaExceeded(SastFixReport),
    MissingApiClient(SastFixReport),
}

pub struct ExecuteSastBulkFixUseCase;

impl ExecuteSastBulkFixUseCase {
    pub async fn execute(
        ctx: &CliContext,
        scan_path: &Path,
        findings: &[SastFinding],
        offline_mode: bool,
    ) -> Result<SastFixExecutionOutcome> {
        let mut report = SastFixReport {
            sast_suggestions: build_sast_suggestions(findings),
            ..SastFixReport::default()
        };

        if offline_mode {
            return Ok(SastFixExecutionOutcome::OfflineMode(report));
        }

        if !ctx.is_authenticated() {
            return Ok(SastFixExecutionOutcome::AuthenticationRequired(report));
        }

        let client = match ctx.api_client() {
            Some(client) => client.clone(),
            None => return Ok(SastFixExecutionOutcome::MissingApiClient(report)),
        };

        if let Ok(deps_response) = client.analyze_dependencies(scan_path, None, false).await {
            report.deps_suggestions = build_deps_suggestions(&deps_response.vulnerabilities);
        }

        let generator = FixGenerator::new(client);

        for finding in findings {
            if finding.line == 0 {
                continue;
            }

            let file_path = resolve_finding_path(scan_path, &finding.file, &ctx.working_dir);
            if !file_path.exists() {
                report.failed_fixes.push(finding.id.clone());
                continue;
            }

            let description = format!("{} [{}]", finding.message, finding.rule_id);
            match generator
                .generate_fix_with_language(
                    &finding.rule_id,
                    &description,
                    &file_path,
                    finding.line,
                    None,
                )
                .await?
            {
                Some(fix) => {
                    report.llm_fixes.push(SastGeneratedFix {
                        finding_id: finding.id.clone(),
                        rule_id: finding.rule_id.clone(),
                        file: finding.file.clone(),
                        line: finding.line,
                        explanation: fix.explanation,
                        suggested_code: fix.suggested_code,
                    });
                }
                None => {
                    report.failed_fixes.push(finding.id.clone());
                }
            }
        }

        Ok(SastFixExecutionOutcome::Success(report))
    }
}

fn resolve_finding_path(scan_path: &Path, finding_file: &str, working_dir: &Path) -> PathBuf {
    let candidate = PathBuf::from(finding_file);
    if candidate.is_absolute() {
        return candidate;
    }

    let from_scan_root = scan_path.join(&candidate);
    if from_scan_root.exists() {
        return from_scan_root;
    }

    working_dir.join(candidate)
}

fn build_sast_suggestions(findings: &[SastFinding]) -> Vec<SastFixSuggestion> {
    let mut seen = HashSet::new();
    let mut suggestions = Vec::new();

    for finding in findings {
        let suggestion = finding
            .fix_suggestion
            .clone()
            .unwrap_or_else(|| format!("Review and remediate rule {}", finding.rule_id));

        let key = format!("{}:{}:{}", finding.file, finding.line, suggestion);
        if seen.insert(key) {
            suggestions.push(SastFixSuggestion {
                finding_id: finding.id.clone(),
                rule_id: finding.rule_id.clone(),
                file: finding.file.clone(),
                line: finding.line,
                suggestion,
            });
        }
    }

    suggestions
}

fn build_deps_suggestions(
    vulnerabilities: &[crate::api_client::SimpleVulnerability],
) -> Vec<SastDepsSuggestion> {
    let mut seen = HashSet::new();
    let mut suggestions = Vec::new();

    for vuln in vulnerabilities {
        let Some(fixed_version) = vuln.fixed_version.clone() else {
            continue;
        };

        let key = format!("{}:{}", vuln.package, fixed_version);
        if seen.insert(key) {
            suggestions.push(SastDepsSuggestion {
                vulnerability_id: vuln.cve.clone().unwrap_or_else(|| vuln.id.clone()),
                package: vuln.package.clone(),
                current_version: vuln.version.clone(),
                suggested_version: fixed_version,
                severity: vuln.severity.clone(),
                suggestion: format!(
                    "Upgrade {} from {} to {}",
                    vuln.package,
                    vuln.version,
                    vuln.fixed_version.as_deref().unwrap_or("latest secure")
                ),
            });
        }
    }

    suggestions
}