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

/// Auto-detect coverage file format from path extension and content, then dispatch to the
/// appropriate parser. Falls back to LCOV for unknown extensions.
#[must_use]
pub fn parse_coverage_auto(path: &Path, content: &str) -> HashMap<PathBuf, FileCoverage> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "xml" => {
            let snip = &content[..content.len().min(512)];
            if snip.contains("<coverage") {
                parse_cobertura(content)
            } else if snip.contains("<report") {
                parse_jacoco(content)
            } else {
                HashMap::new()
            }
        }
        "json" => parse_istanbul(content),
        _ => parse_lcov(content),
    }
}

/// Parse a Cobertura XML coverage file (`coverage.xml`) into a per-file coverage map.
///
/// Cobertura is produced by pytest-cov (`--cov-report xml`), Maven Cobertura plugin, and others.
/// The `filename` attribute on `<class>` is already relative to the project root.
#[must_use]
pub fn parse_cobertura(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();

    // Split on "<class " tokens to get per-class blocks.
    let mut remaining = content;
    while let Some(class_start) = remaining.find("<class ") {
        remaining = &remaining[class_start + 7..];

        // Extract filename="..."
        let filename = match extract_attr(remaining, "filename") {
            Some(f) => f,
            None => continue,
        };

        // Find the end of this class element (either </class> or next <class)
        let class_end = remaining.find("</class>").unwrap_or(remaining.len());
        let class_block = &remaining[..class_end];

        // Count <line elements and hits
        let mut lines_found: u32 = 0;
        let mut lines_hit: u32 = 0;
        let mut method_found: u32 = 0;
        let mut method_hit: u32 = 0;
        let mut branch_found: u32 = 0;
        let mut branch_hit: u32 = 0;

        let mut scan = class_block;
        while let Some(pos) = scan.find("<line ") {
            scan = &scan[pos + 6..];
            lines_found += 1;
            if let Some(hits_str) = extract_attr(scan, "hits") {
                if hits_str.trim() != "0" {
                    lines_hit += 1;
                }
            }
            // branch coverage within <line branch="true" condition-coverage="50% (1/2)">
            if extract_attr(scan, "branch").as_deref() == Some("true") {
                if let Some(cond) = extract_attr(scan, "condition-coverage") {
                    // parse "50% (1/2)" → branch_hit=1, branch_found=2
                    if let Some(frac) = cond.find('(') {
                        let frac_str = &cond[frac + 1..];
                        if let Some(slash) = frac_str.find('/') {
                            let num: u32 = frac_str[..slash].trim().parse().unwrap_or(0);
                            let den_end = frac_str[slash + 1..].find(')').unwrap_or(0);
                            let den: u32 = frac_str[slash + 1..slash + 1 + den_end]
                                .trim()
                                .parse()
                                .unwrap_or(0);
                            branch_hit += num;
                            branch_found += den;
                        }
                    }
                }
            }
        }

        // Count methods from <method elements inside the class block
        let mut mscan = class_block;
        while let Some(pos) = mscan.find("<method ") {
            mscan = &mscan[pos + 8..];
            method_found += 1;
            // A method is "hit" if any of its lines have hits>0; approximate via line-rate attr
            if let Some(lr) = extract_attr(mscan, "line-rate") {
                let rate: f64 = lr.parse().unwrap_or(0.0);
                if rate > 0.0 {
                    method_hit += 1;
                }
            }
        }

        let entry = result
            .entry(PathBuf::from(&filename))
            .or_insert(FileCoverage {
                lines_found: 0,
                lines_hit: 0,
                functions_found: 0,
                functions_hit: 0,
                branches_found: 0,
                branches_hit: 0,
            });
        entry.lines_found += lines_found;
        entry.lines_hit += lines_hit;
        entry.functions_found += method_found;
        entry.functions_hit += method_hit;
        entry.branches_found += branch_found;
        entry.branches_hit += branch_hit;
    }

    result
}

/// Parse a JaCoCo XML report (`jacoco.xml`) into a per-file coverage map.
///
/// JaCoCo is produced by the Gradle `jacocoTestReport` task and the Maven JaCoCo plugin.
/// Paths are reconstructed as `package/sourcefile` (e.g. `com/example/Main.java`).
#[must_use]
pub fn parse_jacoco(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();

    let mut scan = content;
    while let Some(pkg_start) = scan.find("<package ") {
        scan = &scan[pkg_start + 9..];
        let pkg_name = extract_attr(scan, "name").unwrap_or_default();
        let pkg_end = scan.find("</package>").unwrap_or(scan.len());
        let pkg_block = &scan[..pkg_end];

        let mut sf_scan = pkg_block;
        while let Some(sf_start) = sf_scan.find("<sourcefile ") {
            sf_scan = &sf_scan[sf_start + 12..];
            let sf_name = match extract_attr(sf_scan, "name") {
                Some(n) => n,
                None => continue,
            };
            let sf_end = sf_scan.find("</sourcefile>").unwrap_or(sf_scan.len());
            let sf_block = &sf_scan[..sf_end];

            let mut lines_found: u32 = 0;
            let mut lines_hit: u32 = 0;
            let mut fn_found: u32 = 0;
            let mut fn_hit: u32 = 0;
            let mut br_found: u32 = 0;
            let mut br_hit: u32 = 0;

            let mut cscan = sf_block;
            while let Some(cpos) = cscan.find("<counter ") {
                cscan = &cscan[cpos + 9..];
                let ctype = extract_attr(cscan, "type").unwrap_or_default();
                let missed: u32 = extract_attr(cscan, "missed")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let covered: u32 = extract_attr(cscan, "covered")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                match ctype.as_str() {
                    "LINE" => {
                        lines_found = missed + covered;
                        lines_hit = covered;
                    }
                    "METHOD" => {
                        fn_found = missed + covered;
                        fn_hit = covered;
                    }
                    "BRANCH" => {
                        br_found = missed + covered;
                        br_hit = covered;
                    }
                    _ => {}
                }
            }

            let path = if pkg_name.is_empty() {
                PathBuf::from(&sf_name)
            } else {
                PathBuf::from(format!("{}/{}", pkg_name, sf_name))
            };

            result.insert(
                path,
                FileCoverage {
                    lines_found,
                    lines_hit,
                    functions_found: fn_found,
                    functions_hit: fn_hit,
                    branches_found: br_found,
                    branches_hit: br_hit,
                },
            );
        }

        if pkg_end < scan.len() {
            scan = &scan[pkg_end..];
        } else {
            break;
        }
    }

    result
}

/// Parse an Istanbul/NYC `coverage-summary.json` file into a per-file coverage map.
///
/// Istanbul is produced by `nyc --reporter=json-summary` and by many Jest configurations.
/// The top-level keys are absolute file paths.
#[must_use]
pub fn parse_istanbul(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();

    let Ok(root) = serde_json::from_str::<serde_json::Value>(content) else {
        return result;
    };
    let Some(obj) = root.as_object() else {
        return result;
    };

    for (path_str, file_val) in obj {
        // Skip the top-level "total" key
        if path_str == "total" {
            continue;
        }
        let lines_total: u32 = file_val["lines"]["total"].as_u64().unwrap_or(0) as u32;
        let lines_covered: u32 = file_val["lines"]["covered"].as_u64().unwrap_or(0) as u32;
        let fn_total: u32 = file_val["functions"]["total"].as_u64().unwrap_or(0) as u32;
        let fn_covered: u32 = file_val["functions"]["covered"].as_u64().unwrap_or(0) as u32;
        let br_total: u32 = file_val["branches"]["total"].as_u64().unwrap_or(0) as u32;
        let br_covered: u32 = file_val["branches"]["covered"].as_u64().unwrap_or(0) as u32;

        result.insert(
            PathBuf::from(path_str.replace('\\', "/")),
            FileCoverage {
                lines_found: lines_total,
                lines_hit: lines_covered,
                functions_found: fn_total,
                functions_hit: fn_covered,
                branches_found: br_total,
                branches_hit: br_covered,
            },
        );
    }

    result
}

/// Extract the value of a named XML attribute from a fragment of XML text.
/// Handles both `attr="value"` and `attr='value'` quoting.
fn extract_attr(fragment: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=");
    let pos = fragment.find(&needle)?;
    let after = &fragment[pos + needle.len()..];
    let quote = after.chars().next()?;
    if quote == '"' || quote == '\'' {
        let inner = &after[1..];
        let end = inner.find(quote)?;
        Some(inner[..end].to_string())
    } else {
        None
    }
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
