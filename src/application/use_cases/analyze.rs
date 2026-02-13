use std::path::Path;

use crate::application::use_cases::deps::ExecuteDepsScanUseCase;
use crate::commands::analyze::{AnalysisResult, AnalyzeArgs, VulnerabilityInfo};
use crate::context::CliContext;
use crate::severity::severity_meets_minimum_str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepsRunStatus {
    Ran,
    Skipped,
    Failed,
    QuotaExceeded,
}

pub struct AnalyzeExecutionOutcome {
    pub result: AnalysisResult,
    pub deps_status: DepsRunStatus,
}

pub struct ExecuteAnalyzeUseCase;

impl ExecuteAnalyzeUseCase {
    pub async fn execute(
        ctx: &mut CliContext,
        args: &AnalyzeArgs,
        path: &Path,
        offline_mode: bool,
    ) -> AnalyzeExecutionOutcome {
        let mut result = AnalysisResult {
            path: path.to_path_buf(),
            vulnerabilities: Vec::new(),
            summary: crate::commands::analyze::AnalysisSummary {
                total: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                files_scanned: 0,
                duration_ms: 0,
            },
            modules_run: Vec::new(),
            warnings: Vec::new(),
        };

        if !args.skip_sast {
            Self::run_sast_analysis(ctx, path, &mut result).await;
            result.modules_run.push("sast".to_string());
        }

        if !args.skip_secrets {
            Self::run_secrets_analysis(ctx, path, &mut result).await;
            result.modules_run.push("secrets".to_string());
        }

        if !args.skip_api {
            Self::run_api_analysis(ctx, path, &mut result).await;
            result.modules_run.push("api".to_string());
        }

        let deps_status = if args.skip_deps {
            DepsRunStatus::Skipped
        } else if offline_mode {
            result
                .warnings
                .push("Dependency analysis skipped (requires server connection)".to_string());
            DepsRunStatus::Skipped
        } else {
            let status = Self::run_deps_analysis(ctx, path, &mut result, &args.min_severity).await;
            if status == DepsRunStatus::Ran {
                result.modules_run.push("deps".to_string());
            }
            status
        };

        AnalyzeExecutionOutcome { result, deps_status }
    }

    async fn run_sast_analysis(ctx: &CliContext, path: &Path, result: &mut AnalysisResult) {
        match ctx.executor.run_sast(path).await {
            Ok(res) => {
                result.summary.files_scanned += res.files_scanned;

                for finding in res.findings {
                    result.vulnerabilities.push(VulnerabilityInfo {
                        id: finding.rule_id.unwrap_or_else(|| finding.id.clone()),
                        severity: finding.severity,
                        package: finding.file.clone(),
                        version: finding.line.map(|l| format!("L{}", l)).unwrap_or_default(),
                        description: finding.description,
                        module: finding.module,
                        file: Some(finding.file),
                        line: finding.line,
                        fix_available: finding.recommendation.is_some(),
                        fixed_version: None,
                    });
                }
            }
            Err(e) => {
                result.warnings.push(format!("SAST analysis failed: {}", e));
            }
        }
    }

    async fn run_secrets_analysis(ctx: &CliContext, path: &Path, result: &mut AnalysisResult) {
        match ctx.executor.run_secrets(path).await {
            Ok(res) => {
                result.summary.files_scanned += res.files_scanned;

                for finding in res.findings {
                    result.vulnerabilities.push(VulnerabilityInfo {
                        id: finding.rule_id.unwrap_or_else(|| finding.id.clone()),
                        severity: finding.severity,
                        package: finding.file.clone(),
                        version: finding.line.map(|l| format!("L{}", l)).unwrap_or_default(),
                        description: finding.description,
                        module: finding.module,
                        file: Some(finding.file),
                        line: finding.line,
                        fix_available: finding.recommendation.is_some(),
                        fixed_version: None,
                    });
                }
            }
            Err(e) => {
                result
                    .warnings
                    .push(format!("Secret detection failed: {}", e));
            }
        }
    }

    async fn run_api_analysis(ctx: &CliContext, path: &Path, result: &mut AnalysisResult) {
        match ctx.executor.run_api(path).await {
            Ok(res) => {
                for finding in res.findings {
                    result.vulnerabilities.push(VulnerabilityInfo {
                        id: finding.rule_id.unwrap_or_else(|| finding.id.clone()),
                        severity: finding.severity,
                        package: finding.file.clone(),
                        version: finding.line.map(|l| format!("L{}", l)).unwrap_or_default(),
                        description: finding.description,
                        module: finding.module,
                        file: Some(finding.file),
                        line: finding.line,
                        fix_available: finding.recommendation.is_some(),
                        fixed_version: None,
                    });
                }
            }
            Err(e) => {
                let err_msg = e.to_string();
                if !err_msg.contains("No OpenAPI specification found") {
                    result
                        .warnings
                        .push(format!("API security analysis failed: {}", e));
                }
            }
        }
    }

    async fn run_deps_analysis(
        ctx: &mut CliContext,
        path: &Path,
        result: &mut AnalysisResult,
        min_severity: &str,
    ) -> DepsRunStatus {
        match ExecuteDepsScanUseCase::execute(ctx, path, None, false).await {
            Ok(response) => {
                for vuln in response.vulnerabilities {
                    if severity_meets_minimum_str(&vuln.severity, min_severity) {
                        result.vulnerabilities.push(VulnerabilityInfo {
                            id: vuln.cve.unwrap_or(vuln.id),
                            severity: vuln.severity,
                            package: vuln.package.clone(),
                            version: vuln.version,
                            description: vuln.description,
                            module: "deps".to_string(),
                            file: None,
                            line: None,
                            fix_available: vuln.fixed_version.is_some(),
                            fixed_version: vuln.fixed_version,
                        });
                    }
                }
                DepsRunStatus::Ran
            }
            Err(e) => {
                let error_text = e.to_string();
                if error_text.contains("Quota exceeded") {
                    result
                        .warnings
                        .push("Quota exceeded - dependency analysis skipped".to_string());
                    DepsRunStatus::QuotaExceeded
                } else if error_text.contains("requires server connection") {
                    result
                        .warnings
                        .push("Dependency analysis requires server connection".to_string());
                    DepsRunStatus::Skipped
                } else {
                    result
                        .warnings
                        .push(format!("Dependency analysis failed: {}", error_text));
                    DepsRunStatus::Failed
                }
            }
        }
    }
}
