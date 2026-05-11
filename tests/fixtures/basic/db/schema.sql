-- Coverage results schema for the demo project.
-- Stores per-file and aggregate coverage statistics across CI runs.

CREATE TABLE IF NOT EXISTS coverage_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_date     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    git_sha      TEXT,
    branch       TEXT,
    total_lf     INTEGER NOT NULL,   -- lines found
    total_lh     INTEGER NOT NULL,   -- lines hit
    total_brf    INTEGER,            -- branches found
    total_brh    INTEGER,            -- branches hit
    total_fnf    INTEGER,            -- functions found
    total_fnh    INTEGER,            -- functions hit
    notes        TEXT
);

-- Per-file breakdown for a single coverage run.
CREATE TABLE IF NOT EXISTS coverage_files (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         INTEGER NOT NULL REFERENCES coverage_runs(id) ON DELETE CASCADE,
    file_path      TEXT    NOT NULL,
    lines_found    INTEGER NOT NULL,
    lines_hit      INTEGER NOT NULL,
    branches_found INTEGER,
    branches_hit   INTEGER,
    funcs_found    INTEGER,
    funcs_hit      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_coverage_files_run  ON coverage_files(run_id);
CREATE INDEX IF NOT EXISTS idx_coverage_runs_date  ON coverage_runs(run_date);
CREATE INDEX IF NOT EXISTS idx_coverage_runs_sha   ON coverage_runs(git_sha);

-- Handy view: per-file coverage percentages for the most recent run.
CREATE VIEW IF NOT EXISTS v_latest_coverage AS
SELECT
    f.file_path,
    f.lines_hit * 100.0 / NULLIF(f.lines_found, 0)       AS line_pct,
    f.branches_hit * 100.0 / NULLIF(f.branches_found, 0)  AS branch_pct,
    f.funcs_hit * 100.0 / NULLIF(f.funcs_found, 0)        AS func_pct,
    r.git_sha,
    r.branch,
    r.run_date
FROM coverage_files f
JOIN coverage_runs r ON r.id = f.run_id
WHERE r.id = (SELECT MAX(id) FROM coverage_runs);

-- Trend view: aggregate line coverage over time (one row per run).
CREATE VIEW IF NOT EXISTS v_coverage_trend AS
SELECT
    id,
    run_date,
    branch,
    git_sha,
    total_lh * 100.0 / NULLIF(total_lf, 0)   AS line_pct,
    total_brh * 100.0 / NULLIF(total_brf, 0)  AS branch_pct
FROM coverage_runs
ORDER BY run_date DESC;
