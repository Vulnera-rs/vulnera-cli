use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use walkdir::WalkDir;

pub fn collect_changed_files(root: &Path) -> Result<Vec<PathBuf>> {
    let diff_output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("diff")
        .arg("--name-only")
        .arg("--diff-filter=ACMRTUXB")
        .arg("HEAD")
        .output()
        .context("Failed to invoke git for changed files")?;

    if !diff_output.status.success() {
        return Err(anyhow::anyhow!(
            "changed_only requires a git repository and a valid HEAD"
        ));
    }

    let untracked_output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-files")
        .arg("--others")
        .arg("--exclude-standard")
        .output()
        .context("Failed to invoke git for untracked files")?;

    let mut paths = HashSet::new();

    for line in String::from_utf8_lossy(&diff_output.stdout).lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            paths.insert(root.join(trimmed));
        }
    }

    if untracked_output.status.success() {
        for line in String::from_utf8_lossy(&untracked_output.stdout).lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                paths.insert(root.join(trimmed));
            }
        }
    }

    Ok(paths.into_iter().collect())
}

pub fn resolve_scan_targets(
    root: &Path,
    working_dir: &Path,
    explicit_files: &[PathBuf],
    changed_only: bool,
    exclude_patterns: &[String],
    language_filters: Option<&[String]>,
) -> Result<Option<Vec<PathBuf>>> {
    let language_filters = language_filters.unwrap_or(&[]);

    let target_mode = changed_only || !explicit_files.is_empty() || !language_filters.is_empty();
    if !target_mode {
        return Ok(None);
    }

    let mut targets: Vec<PathBuf> = if !explicit_files.is_empty() {
        explicit_files
            .iter()
            .filter_map(|file| resolve_file(root, working_dir, file))
            .collect()
    } else if changed_only {
        collect_changed_files(root)?
    } else {
        collect_files_by_language(root, language_filters)
    };

    if changed_only && !explicit_files.is_empty() {
        let changed_set: HashSet<PathBuf> = collect_changed_files(root)?.into_iter().collect();
        targets.retain(|target| changed_set.contains(target));
    }

    if !language_filters.is_empty() {
        targets.retain(|target| matches_language(target, language_filters));
    }

    targets.retain(|target| !matches_any_pattern(target, exclude_patterns));

    let deduped: HashSet<PathBuf> = targets.into_iter().collect();
    Ok(Some(deduped.into_iter().collect()))
}

pub fn matches_any_pattern(path: &Path, patterns: &[String]) -> bool {
    let path_text = path.to_string_lossy();
    patterns
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .any(|pattern| {
            if pattern.contains('*') {
                let needle = pattern.replace('*', "");
                !needle.is_empty() && path_text.contains(&needle)
            } else {
                path_text.contains(pattern)
                    || path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|name| name == pattern)
            }
        })
}

fn resolve_file(root: &Path, working_dir: &Path, file: &Path) -> Option<PathBuf> {
    let candidate = if file.is_absolute() {
        file.to_path_buf()
    } else {
        let under_root = root.join(file);
        if under_root.exists() {
            under_root
        } else {
            working_dir.join(file)
        }
    };

    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn collect_files_by_language(root: &Path, languages: &[String]) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| matches_language(path, languages))
        .collect()
}

fn matches_language(path: &Path, languages: &[String]) -> bool {
    if languages.is_empty() {
        return true;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let normalized: HashSet<String> = languages
        .iter()
        .map(|l| l.trim().to_ascii_lowercase())
        .collect();

    normalized.contains(&ext)
        || (normalized.contains("rust") && ext == "rs")
        || (normalized.contains("python") && ext == "py")
        || (normalized.contains("javascript") && ["js", "mjs", "cjs"].contains(&ext.as_str()))
        || (normalized.contains("typescript") && ["ts", "tsx", "mts", "cts"].contains(&ext.as_str()))
        || (normalized.contains("go") && ext == "go")
        || (normalized.contains("java") && ext == "java")
        || (normalized.contains("c") && ["c", "h"].contains(&ext.as_str()))
        || (normalized.contains("cpp")
            && ["cpp", "cc", "cxx", "hpp", "hxx"].contains(&ext.as_str()))
}
