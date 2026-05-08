// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Nima Shafie <nimzshafie@gmail.com>

//! Named baseline snapshots — save a scan result as a pinned reference point
//! and compare future scans against it.
//!
//! Baselines are stored in `baselines.json` alongside the scan registry and
//! can be managed via `--set-baseline` / `--fail-above-baseline` CLI flags.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ScanSummarySnapshot;

fn default_baselines_path() -> PathBuf {
    // Mirror the convention used by the web server: relative paths resolve
    // against the current working directory.
    PathBuf::from("out").join("baselines.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub name: String,
    pub saved_at: DateTime<Utc>,
    pub run_id: String,
    pub summary: ScanSummarySnapshot,
    /// Path to the full JSON artifact if still on disk.
    pub json_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineStore {
    pub baselines: BTreeMap<String, BaselineEntry>,
}

impl BaselineStore {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// # Errors
    ///
    /// Returns an error if the file cannot be serialized or written.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self).context("failed to serialize baselines")?;
        std::fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn set(&mut self, entry: BaselineEntry) {
        self.baselines.insert(entry.name.clone(), entry);
    }

    pub fn get(&self, name: &str) -> Option<&BaselineEntry> {
        self.baselines.get(name)
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.baselines.remove(name).is_some()
    }
}

/// Returns the path to the baselines file, honouring `SLOC_BASELINES_PATH`.
pub fn resolve_baselines_path() -> PathBuf {
    std::env::var("SLOC_BASELINES_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_baselines_path())
}

/// Result of a baseline comparison check.
pub struct BaselineCheckResult {
    pub baseline_name: String,
    pub baseline_code_lines: u64,
    pub current_code_lines: u64,
    pub delta: i64,
    pub delta_pct: f64,
    pub exceeded: bool,
    pub max_delta_pct: Option<f64>,
}

impl BaselineCheckResult {
    pub fn print_summary(&self) {
        let sign = if self.delta >= 0 { "+" } else { "" };
        eprintln!(
            "baseline '{}': baseline={} current={} delta={}{} ({:+.1}%)",
            self.baseline_name,
            self.baseline_code_lines,
            self.current_code_lines,
            sign,
            self.delta,
            self.delta_pct,
        );
        if self.exceeded {
            eprintln!(
                "error: code growth {:.1}% exceeds --max-delta-pct {:.1}% (--fail-above-baseline)",
                self.delta_pct,
                self.max_delta_pct.unwrap_or(0.0)
            );
        }
    }
}

/// Compare `current_code_lines` to a stored baseline.
///
/// Returns `Err` if the named baseline does not exist.
pub fn check_against_baseline(
    store: &BaselineStore,
    name: &str,
    current_code_lines: u64,
    max_delta_pct: Option<f64>,
) -> Result<BaselineCheckResult> {
    let entry = store.get(name).ok_or_else(|| {
        anyhow::anyhow!("baseline '{name}' not found; use --set-baseline to create it")
    })?;

    let baseline_code = entry.summary.code_lines;
    let delta = current_code_lines as i64 - baseline_code as i64;
    let delta_pct = if baseline_code == 0 {
        0.0
    } else {
        (delta as f64 / baseline_code as f64) * 100.0
    };

    let exceeded = max_delta_pct.is_some_and(|limit| delta_pct > limit);

    Ok(BaselineCheckResult {
        baseline_name: name.to_owned(),
        baseline_code_lines: baseline_code,
        current_code_lines,
        delta,
        delta_pct,
        exceeded,
        max_delta_pct,
    })
}
