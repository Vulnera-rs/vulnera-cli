use crate::exit_codes;

pub fn findings_exit_code(fail_on_finding: bool, has_findings: bool) -> i32 {
    if fail_on_finding && has_findings {
        exit_codes::VULNERABILITIES_FOUND
    } else {
        exit_codes::SUCCESS
    }
}

pub fn analyze_exit_code(quota_exceeded: bool, fail_on_finding: bool, has_findings: bool) -> i32 {
    if quota_exceeded {
        exit_codes::QUOTA_EXCEEDED
    } else {
        findings_exit_code(fail_on_finding, has_findings)
    }
}

pub fn is_findings_exit(exit_code: i32) -> bool {
    exit_code == exit_codes::VULNERABILITIES_FOUND
}
