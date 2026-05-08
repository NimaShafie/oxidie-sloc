use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Per-file coverage metrics parsed from an LCOV `.info` file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileCoverage {
    pub lines_found: u32,
    pub lines_hit: u32,
    pub functions_found: u32,
    pub functions_hit: u32,
    pub branches_found: u32,
    pub branches_hit: u32,
}

impl FileCoverage {
    #[must_use]
    pub fn line_pct(&self) -> f64 {
        if self.lines_found == 0 {
            0.0
        } else {
            (self.lines_hit as f64 / self.lines_found as f64) * 100.0
        }
    }

    #[must_use]
    pub fn function_pct(&self) -> f64 {
        if self.functions_found == 0 {
            0.0
        } else {
            (self.functions_hit as f64 / self.functions_found as f64) * 100.0
        }
    }

    #[must_use]
    pub fn branch_pct(&self) -> f64 {
        if self.branches_found == 0 {
            0.0
        } else {
            (self.branches_hit as f64 / self.branches_found as f64) * 100.0
        }
    }
}

/// Parse an LCOV `.info` file and return a map from source file path to coverage metrics.
///
/// Paths in the map are normalised to forward-slash separators and stored as-is from the
/// `SF:` record — callers are responsible for matching against `FileRecord.relative_path`.
#[must_use]
pub fn parse_lcov(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();

    let mut current_path: Option<PathBuf> = None;
    let mut lf: u32 = 0;
    let mut lh: u32 = 0;
    let mut fnf: u32 = 0;
    let mut fnh: u32 = 0;
    let mut brf: u32 = 0;
    let mut brh: u32 = 0;

    for line in content.lines() {
        let line = line.trim();
        if let Some(path_str) = line.strip_prefix("SF:") {
            current_path = Some(PathBuf::from(path_str.replace('\\', "/")));
            lf = 0;
            lh = 0;
            fnf = 0;
            fnh = 0;
            brf = 0;
            brh = 0;
        } else if line == "end_of_record" {
            if let Some(path) = current_path.take() {
                result.insert(
                    path,
                    FileCoverage {
                        lines_found: lf,
                        lines_hit: lh,
                        functions_found: fnf,
                        functions_hit: fnh,
                        branches_found: brf,
                        branches_hit: brh,
                    },
                );
            }
        } else if let Some(val) = line.strip_prefix("LF:") {
            lf = val.parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("LH:") {
            lh = val.parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("FNF:") {
            fnf = val.parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("FNH:") {
            fnh = val.parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("BRF:") {
            brf = val.parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("BRH:") {
            brh = val.parse().unwrap_or(0);
        }
    }

    result
}

/// Attempt to match a `FileRecord`'s `relative_path` against the coverage map.
///
/// LCOV paths are typically absolute (`/path/to/repo/src/foo.c`) while oxide-sloc stores
/// relative paths (`src/foo.c`). This function tries three strategies in order:
/// 1. Direct `PathBuf` key lookup (exact match or already-relative paths)
/// 2. Suffix match: find a coverage path whose components end with the relative path
/// 3. Filename-only fallback when the relative path is a bare filename
#[must_use]
pub fn lookup_coverage<'a>(
    map: &'a HashMap<PathBuf, FileCoverage>,
    relative_path: &str,
) -> Option<&'a FileCoverage> {
    let rel = PathBuf::from(relative_path.replace('\\', "/"));

    // Strategy 1: exact key
    if let Some(cov) = map.get(&rel) {
        return Some(cov);
    }

    // Strategy 2: any coverage path whose tail matches the relative path
    let rel_components: Vec<_> = rel.components().collect();
    for (cov_path, cov) in map {
        let cov_components: Vec<_> = cov_path.components().collect();
        if cov_components.len() >= rel_components.len()
            && cov_components[cov_components.len() - rel_components.len()..] == rel_components[..]
        {
            return Some(cov);
        }
    }

    // Strategy 3: filename-only fallback
    let filename = rel.file_name()?;
    for (cov_path, cov) in map {
        if cov_path.file_name() == Some(filename) {
            return Some(cov);
        }
    }

    None
}

/// Compute a weighted-average line coverage percentage across all files that have coverage data.
/// Returns `None` if no files have coverage data or if total `lines_found` is zero.
#[must_use]
pub fn aggregate_line_coverage(records: &[&FileCoverage]) -> Option<f64> {
    let total_found: u64 = records.iter().map(|c| u64::from(c.lines_found)).sum();
    if total_found == 0 {
        return None;
    }
    let total_hit: u64 = records.iter().map(|c| u64::from(c.lines_hit)).sum();
    Some((total_hit as f64 / total_found as f64) * 100.0)
}

/// Resolve a coverage file path from the environment variable `SLOC_COVERAGE_FILE` or the
/// provided config path, normalising to an absolute `PathBuf`.
#[must_use]
pub fn resolve_coverage_file(config_path: Option<&Path>) -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("SLOC_COVERAGE_FILE") {
        if !env_path.is_empty() {
            return Some(PathBuf::from(env_path));
        }
    }
    config_path.map(PathBuf::from)
}
