// SPDX-License-Identifier: AGPL-3.0-or-later
// Coverage-gap tests for sloc-config: serde default helpers reached by loading a
// bare TOML, and the AppConfig::validate() -> BudgetConfig::validate() path.

use std::collections::BTreeMap;

use sloc_config::{AppConfig, BudgetConfig};

/// Loading a TOML that omits the `[reporting]` and `[web]` sections forces serde to
/// fall back on the `default_*` helper functions (report title, output formats,
/// theme, bind address, etc.).
#[test]
fn load_bare_toml_uses_reporting_and_web_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sloc.toml");
    // Only a comment — every section is absent, so all defaults kick in.
    std::fs::write(&path, "# empty config\n").unwrap();

    let cfg = AppConfig::load_from_file(&path).unwrap();

    assert_eq!(cfg.reporting.report_title, "OxideSLOC Report");
    assert_eq!(cfg.web.bind_address, "127.0.0.1:4317");
    assert!(
        cfg.reporting.output_formats.contains(&"json".to_string()),
        "default output formats should include json: {:?}",
        cfg.reporting.output_formats
    );
    assert_eq!(cfg.reporting.theme, "auto");
    // The whole thing must still validate.
    assert!(cfg.validate().is_ok());
}

/// A valid budget on the analysis config makes AppConfig::validate() call through to
/// BudgetConfig::validate() and succeed.
#[test]
fn app_config_validate_accepts_valid_budget() {
    let mut cfg = AppConfig::default();
    let mut per_language = BTreeMap::new();
    per_language.insert("rust".to_string(), 50_000_u64);
    cfg.analysis.budget = Some(BudgetConfig {
        total_max: 100_000,
        per_language,
    });
    assert!(
        cfg.validate().is_ok(),
        "a positive budget should validate cleanly"
    );
}

/// A budget with a zero per-language limit makes AppConfig::validate() surface the
/// BudgetConfig::validate() error (the `analysis.budget is invalid` context path).
#[test]
fn app_config_validate_rejects_zero_per_language_budget() {
    let mut cfg = AppConfig::default();
    let mut per_language = BTreeMap::new();
    per_language.insert("python".to_string(), 0_u64);
    cfg.analysis.budget = Some(BudgetConfig {
        total_max: 0,
        per_language,
    });
    let err = cfg.validate().unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("budget"),
        "error should mention the invalid budget: {msg}"
    );
}
