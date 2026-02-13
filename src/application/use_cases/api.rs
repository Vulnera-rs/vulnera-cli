use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use uuid::Uuid;
use vulnera_api::module::ApiSecurityModule;
use vulnera_core::domain::module::{AnalysisModule, ModuleConfig};

use crate::commands::api::{ApiArgs, ApiFinding, ApiResult, ApiSummary};
use crate::severity::{parse_severity, severity_meets_minimum};

pub enum ApiExecutionOutcome {
    Success(ApiResult),
    NoSpecFound,
}

pub struct ExecuteApiScanUseCase;

impl ExecuteApiScanUseCase {
    pub async fn execute(args: &ApiArgs, source_path: &Path) -> Result<ApiExecutionOutcome> {
        let min_severity = parse_severity(&args.min_severity);

        let api_module = ApiSecurityModule::new();
        let module_config = ModuleConfig {
            job_id: Uuid::new_v4(),
            project_id: "cli-local".to_string(),
            source_uri: source_path.to_string_lossy().to_string(),
            config: Default::default(),
        };

        let res = match api_module.execute(&module_config).await {
            Ok(res) => res,
            Err(e) => {
                if e.to_string().contains("No OpenAPI specification found") {
                    return Ok(ApiExecutionOutcome::NoSpecFound);
                }
                return Err(e.into());
            }
        };

        let findings: Vec<ApiFinding> = res
            .findings
            .into_iter()
            .filter(|f| severity_meets_minimum(&f.severity, &min_severity))
            .map(|f| ApiFinding {
                id: f.id,
                severity: format!("{:?}", f.severity).to_lowercase(),
                category: f.rule_id.unwrap_or_else(|| "api-security".to_string()),
                endpoint: extract_endpoint(&f.description),
                method: extract_method(&f.description),
                issue: f.description.clone(),
                description: f.description,
                file: Some(f.location.path),
                line: f.location.line,
                owasp_category: None,
                remediation: f
                    .recommendation
                    .unwrap_or_else(|| "Review and fix the identified API security issue".to_string()),
            })
            .collect();

        let mut summary = ApiSummary {
            total_findings: findings.len(),
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            endpoints_analyzed: 0,
            by_category: HashMap::new(),
        };

        for finding in &findings {
            match finding.severity.as_str() {
                "critical" => summary.critical += 1,
                "high" => summary.high += 1,
                "medium" => summary.medium += 1,
                "low" => summary.low += 1,
                _ => {}
            }
            *summary
                .by_category
                .entry(finding.category.clone())
                .or_insert(0) += 1;
        }

        Ok(ApiExecutionOutcome::Success(ApiResult {
            path: source_path.to_path_buf(),
            spec_file: if source_path.is_file() {
                Some(source_path.to_string_lossy().to_string())
            } else {
                None
            },
            framework: args.framework.clone(),
            endpoints_found: summary.endpoints_analyzed,
            findings,
            summary,
        }))
    }
}

fn extract_endpoint(description: &str) -> String {
    if let Some(start) = description.find('/') {
        let end = description[start..]
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .map(|i| start + i)
            .unwrap_or(description.len());
        return description[start..end].to_string();
    }
    "N/A".to_string()
}

fn extract_method(description: &str) -> String {
    let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
    for method in methods {
        if description.contains(method) {
            return method.to_string();
        }
    }
    "N/A".to_string()
}
