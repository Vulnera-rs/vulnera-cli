use std::path::Path;

use crate::application::services::scan_targets::collect_changed_files;
use crate::application::use_cases::deps::ExecuteDepsScanUseCase;
use crate::application::use_cases::sast::ExecuteSastScanUseCase;
use crate::application::use_cases::secrets::ExecuteSecretsScanUseCase;
use crate::commands::sast::SastArgs;
use crate::commands::secrets::SecretsArgs;
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
            Self::run_sast_analysis(ctx, path, args, &mut result).await;
            result.modules_run.push("sast".to_string());
        }

        if !args.skip_secrets {
            Self::run_secrets_analysis(ctx, path, args, &mut result).await;
            result.modules_run.push("secrets".to_string());
        }

        if !args.skip_api {
            Self::run_api_analysis(ctx, path, args.changed_only, &mut result).await;
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
            let status = Self::run_deps_analysis(
                ctx,
                path,
                &mut result,
                &args.min_severity,
                args.changed_only,
            )
            .await;
            if status == DepsRunStatus::Ran {
                result.modules_run.push("deps".to_string());
            }
            status
        };

        AnalyzeExecutionOutcome { result, deps_status }
    }

    async fn run_sast_analysis(
        ctx: &CliContext,
        path: &Path,
        args: &AnalyzeArgs,
        result: &mut AnalysisResult,
    ) {
        let mapped = SastArgs {
            path: path.to_path_buf(),
            min_severity: args.min_severity.clone(),
            fail_on_vuln: false,
            changed_only: args.changed_only,
            files: Vec::new(),
            exclude: args.exclude.clone(),
            languages: Vec::new(),
            rules: Vec::new(),
            no_cache: false,
            watch: false,
            fix: false,
        };

        match ExecuteSastScanUseCase::execute(ctx, &mapped, path).await {
            Ok(scan) => {
                result.summary.files_scanned += scan.files_scanned;

                for finding in scan.findings {
                    result.vulnerabilities.push(VulnerabilityInfo {
                        id: finding.rule_id,
                        severity: finding.severity,
                        package: finding.file.clone(),
                        version: format!("L{}", finding.line),
                        description: finding.message,
                        module: "sast".to_string(),
                        file: Some(finding.file),
                        line: Some(finding.line),
                        fix_available: finding.fix_suggestion.is_some(),
                        fixed_version: None,
                    });
                }
            }
            Err(e) => {
                result.warnings.push(format!("SAST analysis failed: {}", e));
            }
        }
    }

    async fn run_secrets_analysis(
        ctx: &CliContext,
        path: &Path,
        args: &AnalyzeArgs,
        result: &mut AnalysisResult,
    ) {
        let mapped = SecretsArgs {
            path: path.to_path_buf(),
            fail_on_secret: false,
            changed_only: args.changed_only,
            files: Vec::new(),
            exclude: args.exclude.clone(),
            include_tests: true,
            include_entropy: true,
            no_cache: false,
            watch: false,
        };

        match ExecuteSecretsScanUseCase::execute(ctx, &mapped, path).await {
            Ok(scan) => {
                result.summary.files_scanned += scan.files_scanned;

                for finding in scan.findings {
                    result.vulnerabilities.push(VulnerabilityInfo {
                        id: finding.secret_type,
                        severity: finding.severity,
                        package: finding.file.clone(),
                        version: format!("L{}", finding.line),
                        description: finding.description,
                        module: "secrets".to_string(),
                        file: Some(finding.file),
                        line: Some(finding.line),
                        fix_available: true,
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

    async fn run_api_analysis(
        ctx: &CliContext,
        path: &Path,
        changed_only: bool,
        result: &mut AnalysisResult,
    ) {
        let changed_api_targets = if changed_only {
            collect_changed_files(path)
            .ok()
            .map(|files| {
                files
                    .into_iter()
                    .filter(|f| {
                        f.extension()
                            .and_then(|e| e.to_str())
                            .is_some_and(|ext| matches!(ext, "yaml" | "yml" | "json"))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
        } else {
            Vec::new()
        };

        if changed_only && changed_api_targets.is_empty() {
            result
                .warnings
                .push("API analysis skipped (no changed API spec files)".to_string());
            return;
        }

        if !changed_api_targets.is_empty() {
            for target in changed_api_targets {
                match ctx.executor.run_api(&target).await {
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
            return;
        }

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
        changed_only: bool,
    ) -> DepsRunStatus {
        if changed_only
            && let Ok(changed_files) = collect_changed_files(path)
        {
            let manifest_changed = changed_files.iter().any(|file| {
                file.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
                    matches!(
                        name,
                        "package.json"
                            | "package-lock.json"
                            | "yarn.lock"
                            | "pnpm-lock.yaml"
                            | "Cargo.toml"
                            | "Cargo.lock"
                            | "requirements.txt"
                            | "Pipfile"
                            | "pyproject.toml"
                            | "pom.xml"
                            | "build.gradle"
                            | "go.mod"
                    )
                })
            });

            if !manifest_changed {
                result.warnings.push(
                    "Dependency analysis skipped (no changed dependency manifests)".to_string(),
                );
                return DepsRunStatus::Skipped;
            }
        }

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
