use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Per-file coverage metrics parsed from a coverage report.
///
/// Supported source formats (see `parse_coverage_auto`): LCOV `.info` (lcov, gcov,
/// cargo-llvm-cov), Cobertura XML, `JaCoCo` XML, Istanbul/NYC `json-summary`, and coverage.py
/// native JSON (`coverage json`).
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
            (f64::from(self.lines_hit) / f64::from(self.lines_found)) * 100.0
        }
    }

    #[must_use]
    pub fn function_pct(&self) -> f64 {
        if self.functions_found == 0 {
            0.0
        } else {
            (f64::from(self.functions_hit) / f64::from(self.functions_found)) * 100.0
        }
    }

    #[must_use]
    pub fn branch_pct(&self) -> f64 {
        if self.branches_found == 0 {
            0.0
        } else {
            (f64::from(self.branches_hit) / f64::from(self.branches_found)) * 100.0
        }
    }
}

/// Per-record accumulator for a single `SF:` block while parsing LCOV.
///
/// LCOV files may carry the `LF/LH/FNF/FNH/BRF/BRH` summary records, the raw per-line
/// `DA:`/`FNDA:`/`BRDA:` records, or both. Some producers (notably `llvm-cov export -format=lcov`
/// and certain `geninfo` configurations) emit only the raw records and omit the summaries. We
/// track both and prefer the explicit summary when present, falling back to counts derived from
/// the raw records so coverage is never silently reported as zero.
#[derive(Default)]
struct LcovRecord {
    // Explicit summary records (and whether each was seen).
    lf: u32,
    lh: u32,
    fnf: u32,
    fnh: u32,
    brf: u32,
    brh: u32,
    saw_lf: bool,
    saw_lh: bool,
    saw_fnf: bool,
    saw_fnh: bool,
    saw_brf: bool,
    saw_brh: bool,
    // Counts derived from raw DA:/FN:/FNDA:/BRDA: records.
    da_found: u32,
    da_hit: u32,
    fn_found: u32,
    fnda_hit: u32,
    brda_found: u32,
    brda_hit: u32,
}

impl LcovRecord {
    /// Resolve the final `FileCoverage`, preferring explicit summaries over derived counts.
    fn finalize(&self) -> FileCoverage {
        FileCoverage {
            lines_found: if self.saw_lf { self.lf } else { self.da_found },
            lines_hit: if self.saw_lh { self.lh } else { self.da_hit },
            functions_found: if self.saw_fnf {
                self.fnf
            } else {
                self.fn_found
            },
            functions_hit: if self.saw_fnh {
                self.fnh
            } else {
                self.fnda_hit
            },
            branches_found: if self.saw_brf {
                self.brf
            } else {
                self.brda_found
            },
            branches_hit: if self.saw_brh {
                self.brh
            } else {
                self.brda_hit
            },
        }
    }
}

/// True when an LCOV `DA:`/`FNDA:` hit count field is non-zero (execution count > 0).
fn lcov_count_nonzero(field: &str) -> bool {
    !matches!(field.trim(), "" | "0" | "-")
}

/// Parse an LCOV `.info` file and return a map from source file path to coverage metrics.
///
/// Paths in the map are normalised to forward-slash separators and stored as-is from the
/// `SF:` record — callers are responsible for matching against `FileRecord.relative_path`.
///
/// Both the summary records (`LF/LH/FNF/FNH/BRF/BRH`) and the raw per-line records
/// (`DA:`/`FN:`/`FNDA:`/`BRDA:`) are understood. When a summary record is absent, the
/// corresponding value is derived from the raw records so files that ship only raw data still
/// report accurate coverage.
#[must_use]
pub fn parse_lcov(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();

    let mut current_path: Option<PathBuf> = None;
    let mut rec = LcovRecord::default();

    for line in content.lines() {
        let line = line.trim();
        if let Some(path_str) = line.strip_prefix("SF:") {
            current_path = Some(PathBuf::from(path_str.replace('\\', "/")));
            rec = LcovRecord::default();
        } else if line == "end_of_record" {
            if let Some(path) = current_path.take() {
                result.insert(path, rec.finalize());
            }
            rec = LcovRecord::default();
        } else if let Some(val) = line.strip_prefix("LF:") {
            rec.lf = val.parse().unwrap_or(0);
            rec.saw_lf = true;
        } else if let Some(val) = line.strip_prefix("LH:") {
            rec.lh = val.parse().unwrap_or(0);
            rec.saw_lh = true;
        } else if let Some(val) = line.strip_prefix("FNF:") {
            rec.fnf = val.parse().unwrap_or(0);
            rec.saw_fnf = true;
        } else if let Some(val) = line.strip_prefix("FNH:") {
            rec.fnh = val.parse().unwrap_or(0);
            rec.saw_fnh = true;
        } else if let Some(val) = line.strip_prefix("BRF:") {
            rec.brf = val.parse().unwrap_or(0);
            rec.saw_brf = true;
        } else if let Some(val) = line.strip_prefix("BRH:") {
            rec.brh = val.parse().unwrap_or(0);
            rec.saw_brh = true;
        } else if let Some(val) = line.strip_prefix("DA:") {
            // DA:<line>,<hits>[,checksum]
            rec.da_found += 1;
            if val.split(',').nth(1).is_some_and(lcov_count_nonzero) {
                rec.da_hit += 1;
            }
        } else if line.starts_with("FN:") {
            // FN:<line>,<name> — one function definition.
            rec.fn_found += 1;
        } else if let Some(val) = line.strip_prefix("FNDA:") {
            // FNDA:<hits>,<name> — execution count for a function.
            if val.split(',').next().is_some_and(lcov_count_nonzero) {
                rec.fnda_hit += 1;
            }
        } else if let Some(val) = line.strip_prefix("BRDA:") {
            // BRDA:<line>,<block>,<branch>,<taken> — taken is "-" when the branch was not reached.
            rec.brda_found += 1;
            if val.split(',').nth(3).is_some_and(lcov_count_nonzero) {
                rec.brda_hit += 1;
            }
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
#[allow(clippy::implicit_hasher)] // public API; callers always use the default hasher
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
            tracing::debug!(file = relative_path, matched_as = %cov_path.display(), strategy = "suffix", "coverage matched");
            return Some(cov);
        }
    }

    // Strategy 3: filename-only fallback
    let filename = rel.file_name()?;
    for (cov_path, cov) in map {
        if cov_path.file_name() == Some(filename) {
            tracing::debug!(file = relative_path, matched_as = %cov_path.display(), strategy = "filename", "coverage matched (ambiguous)");
            return Some(cov);
        }
    }

    tracing::debug!(file = relative_path, "no coverage entry found");
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
    // ratio/percentage display, precision loss acceptable
    #[allow(clippy::cast_precision_loss)]
    Some((total_hit as f64 / total_found as f64) * 100.0)
}

/// Auto-detect coverage file format from path extension and content, then dispatch to the
/// appropriate parser.
///
/// `.xml` is sniffed for Cobertura vs `JaCoCo`; `.json` is sniffed for coverage.py native JSON
/// vs Istanbul `json-summary`. Falls back to LCOV for unknown extensions.
#[must_use]
pub fn parse_coverage_auto(path: &Path, content: &str) -> HashMap<PathBuf, FileCoverage> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let result = match ext.as_str() {
        "xml" => {
            let snip = &content[..content.len().min(512)];
            if snip.contains("<coverage") {
                tracing::debug!(path = %path.display(), format = "cobertura", bytes = content.len(), "parsing coverage file");
                parse_cobertura(content)
            } else if snip.contains("<report") {
                tracing::debug!(path = %path.display(), format = "jacoco", bytes = content.len(), "parsing coverage file");
                parse_jacoco(content)
            } else {
                tracing::warn!(path = %path.display(), "coverage XML file has unrecognised root element; skipping");
                HashMap::new()
            }
        }
        "json" => {
            // coverage.py's native `coverage json` output nests files under a top-level `files`
            // object alongside a `meta` block; Istanbul's `json-summary` keys files at the top
            // level. Sniff for the coverage.py signature before falling back to Istanbul.
            if content.contains("\"files\"") && content.contains("\"meta\"") {
                tracing::debug!(path = %path.display(), format = "coverage.py", bytes = content.len(), "parsing coverage file");
                parse_coverage_py(content)
            } else {
                tracing::debug!(path = %path.display(), format = "istanbul", bytes = content.len(), "parsing coverage file");
                parse_istanbul(content)
            }
        }
        _ => {
            tracing::debug!(path = %path.display(), format = "lcov", bytes = content.len(), "parsing coverage file");
            parse_lcov(content)
        }
    };
    tracing::debug!(path = %path.display(), file_count = result.len(), "coverage parse complete");
    result
}

/// Parse a Cobertura XML coverage file (`coverage.xml`) into a per-file coverage map.
///
/// Cobertura is produced by pytest-cov (`--cov-report xml`), Maven Cobertura plugin, and others.
/// The `filename` attribute on `<class>` is already relative to the project root.
#[must_use]
pub fn parse_cobertura(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();
    let mut remaining = content;
    while let Some(class_start) = remaining.find("<class ") {
        remaining = &remaining[class_start + 7..];
        let Some(filename) = extract_attr(remaining, "filename") else {
            continue;
        };
        let class_end = remaining.find("</class>").unwrap_or(remaining.len());
        let class_block = &remaining[..class_end];
        let (lines_found, lines_hit, branch_found, branch_hit) = cobertura_scan_lines(class_block);
        let (method_found, method_hit) = cobertura_scan_methods(class_block);
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

/// Count `<line>` hits and branch coverage within a Cobertura `<class>` block.
fn cobertura_scan_lines(class_block: &str) -> (u32, u32, u32, u32) {
    let mut lines_found: u32 = 0;
    let mut lines_hit: u32 = 0;
    let mut branch_found: u32 = 0;
    let mut branch_hit: u32 = 0;
    let mut scan = class_block;
    while let Some(pos) = scan.find("<line ") {
        scan = &scan[pos + 6..];
        lines_found += 1;
        if extract_attr(scan, "hits").is_some_and(|h| h.trim() != "0") {
            lines_hit += 1;
        }
        if extract_attr(scan, "branch").as_deref() == Some("true") {
            let (hit, found) = parse_cobertura_branch_fraction(scan);
            branch_hit += hit;
            branch_found += found;
        }
    }
    (lines_found, lines_hit, branch_found, branch_hit)
}

/// Parse `condition-coverage="50% (1/2)"` → `(hit=1, found=2)`.
fn parse_cobertura_branch_fraction(scan: &str) -> (u32, u32) {
    let Some(cond) = extract_attr(scan, "condition-coverage") else {
        return (0, 0);
    };
    let Some(frac_start) = cond.find('(') else {
        return (0, 0);
    };
    let frac_str = &cond[frac_start + 1..];
    let Some(slash) = frac_str.find('/') else {
        return (0, 0);
    };
    let num: u32 = frac_str[..slash].trim().parse().unwrap_or(0);
    let den_end = frac_str[slash + 1..].find(')').unwrap_or(0);
    let den: u32 = frac_str[slash + 1..slash + 1 + den_end]
        .trim()
        .parse()
        .unwrap_or(0);
    (num, den)
}

/// Count `<method>` elements and how many have a non-zero line-rate in a Cobertura class block.
fn cobertura_scan_methods(class_block: &str) -> (u32, u32) {
    let mut method_found: u32 = 0;
    let mut method_hit: u32 = 0;
    let mut mscan = class_block;
    while let Some(pos) = mscan.find("<method ") {
        mscan = &mscan[pos + 8..];
        method_found += 1;
        let rate: f64 = extract_attr(mscan, "line-rate")
            .and_then(|lr| lr.parse().ok())
            .unwrap_or(0.0);
        if rate > 0.0 {
            method_hit += 1;
        }
    }
    (method_found, method_hit)
}

/// Parse a `JaCoCo` XML report (`jacoco.xml`) into a per-file coverage map.
///
/// `JaCoCo` is produced by the Gradle `jacocoTestReport` task and the Maven `JaCoCo` plugin.
/// Paths are reconstructed as `package/sourcefile` (e.g. `com/example/Main.java`).
#[must_use]
pub fn parse_jacoco(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();
    let mut scan = content;
    while let Some(pkg_start) = scan.find("<package ") {
        scan = &scan[pkg_start + 9..];
        let pkg_name = extract_attr(scan, "name").unwrap_or_default();
        let pkg_end = scan.find("</package>").unwrap_or(scan.len());
        parse_jacoco_package(&scan[..pkg_end], &pkg_name, &mut result);
        if pkg_end < scan.len() {
            scan = &scan[pkg_end..];
        } else {
            break;
        }
    }
    result
}

fn parse_jacoco_package(
    pkg_block: &str,
    pkg_name: &str,
    result: &mut HashMap<PathBuf, FileCoverage>,
) {
    let mut sf_scan = pkg_block;
    while let Some(sf_start) = sf_scan.find("<sourcefile ") {
        sf_scan = &sf_scan[sf_start + 12..];
        let Some(sf_name) = extract_attr(sf_scan, "name") else {
            continue;
        };
        let sf_end = sf_scan.find("</sourcefile>").unwrap_or(sf_scan.len());
        let cov = parse_jacoco_counters(&sf_scan[..sf_end]);
        let path = if pkg_name.is_empty() {
            PathBuf::from(&sf_name)
        } else {
            PathBuf::from(format!("{pkg_name}/{sf_name}"))
        };
        result.insert(path, cov);
    }
}

fn parse_jacoco_counters(sf_block: &str) -> FileCoverage {
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
    FileCoverage {
        lines_found,
        lines_hit,
        functions_found: fn_found,
        functions_hit: fn_hit,
        branches_found: br_found,
        branches_hit: br_hit,
    }
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
        // Line/function/branch counts are always small; truncation is not possible in practice.
        #[allow(clippy::cast_possible_truncation)]
        let lines_total: u32 = file_val["lines"]["total"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let lines_covered: u32 = file_val["lines"]["covered"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let fn_total: u32 = file_val["functions"]["total"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let fn_covered: u32 = file_val["functions"]["covered"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let br_total: u32 = file_val["branches"]["total"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
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

/// Parse a coverage.py native JSON report (`coverage json`) into a per-file coverage map.
///
/// coverage.py's own JSON schema differs from Istanbul's `json-summary`: it nests per-file data
/// under a top-level `files` object, with line/branch counts in each file's `summary` block.
/// coverage.py does not track function-level coverage, so `functions_*` are always zero.
#[must_use]
pub fn parse_coverage_py(content: &str) -> HashMap<PathBuf, FileCoverage> {
    let mut result: HashMap<PathBuf, FileCoverage> = HashMap::new();

    let Ok(root) = serde_json::from_str::<serde_json::Value>(content) else {
        return result;
    };
    let Some(files) = root.get("files").and_then(serde_json::Value::as_object) else {
        return result;
    };

    for (path_str, file_val) in files {
        let summary = &file_val["summary"];
        // Line/branch counts are always small; truncation is not possible in practice.
        #[allow(clippy::cast_possible_truncation)]
        let lines_found: u32 = summary["num_statements"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let lines_hit: u32 = summary["covered_lines"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let br_found: u32 = summary["num_branches"].as_u64().unwrap_or(0) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let br_hit: u32 = summary["covered_branches"].as_u64().unwrap_or(0) as u32;

        result.insert(
            PathBuf::from(path_str.replace('\\', "/")),
            FileCoverage {
                lines_found,
                lines_hit,
                functions_found: 0,
                functions_hit: 0,
                branches_found: br_found,
                branches_hit: br_hit,
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
