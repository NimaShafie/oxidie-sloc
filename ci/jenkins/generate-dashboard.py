"""oxide-sloc CI build dashboard generator.

Reads CI output artifacts from <output-dir> and writes a single self-contained
HTML file with inline SVG charts and CSS.  Requires only Python 3 standard library —
no pip installs, no external JS libraries, and no Jenkins plugins beyond the core
``archiveArtifacts`` step.

Usage
-----
    python3 ci/jenkins/generate-dashboard.py <output-dir> [project-slug]

Arguments
---------
output-dir
    Directory that contains the CI output artifacts produced by the Jenkinsfile.
    Typically the value of the ``OUTPUT_SUBDIR`` pipeline parameter (e.g. ``ci-out``).

project-slug
    Optional.  If omitted the script auto-detects it from the first
    ``result_*.json`` file found in <output-dir>.

Inputs (all relative to <output-dir>)
--------------------------------------
result_<slug>.json
    SLOC metrics produced by ``oxide-sloc analyze --json-out``.  Required.
test-results/junit.xml
    JUnit XML produced by cargo-nextest.  Optional.
coverage/lcov.info
    LCOV coverage data produced by cargo-llvm-cov.  Optional.

Output
------
<output-dir>/dashboard_<slug>.html
    Self-contained HTML file.  Path is printed to stdout on success.

Environment variables read
--------------------------
BUILD_NUMBER   Jenkins build number shown in the header.
BUILD_URL      Jenkins build URL — used for the "← Back to Jenkins build" link.
JOB_NAME       Jenkins job name shown in the header.
SCAN_PATH      Path that was scanned (shown in the header).
"""

import html
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from glob import glob
from typing import Optional
import csv


# ---------------------------------------------------------------------------
# Number formatting (matches the CLAUDE.md canonical spec)
# ---------------------------------------------------------------------------

def fmt(n: int) -> str:
    """Compact number formatter.

    < 1,000          → as-is with Python locale comma (e.g. "2", "947")
    1,000 – 9,999    → comma-separated (e.g. "1,247")
    10,000 – 999,999 → integer K  (e.g. "15K", "100K")
    >= 1,000,000     → one-decimal M, trailing .0 stripped (e.g. "3.8M")
    """
    v = int(n)
    a = abs(v)
    if a >= 1_000_000:
        m = v / 1_000_000
        s = f"{m:.1f}M"
        return s.replace(".0M", "M")
    if a >= 10_000:
        return f"{round(v / 1_000)}K"
    return f"{v:,}"


def fmt_full(n: int) -> str:
    """Full precision comma-formatted number for tooltips."""
    return f"{int(n):,}"


# ---------------------------------------------------------------------------
# SVG helpers
# ---------------------------------------------------------------------------

# Ten-colour oxide palette (warm browns / terracottas)
_OXIDE_PALETTE = [
    "#b04a00", "#d4691c", "#a03800", "#cc5800",
    "#e07038", "#8a3800", "#e89060", "#c04818",
    "#f0a070", "#943000",
]


def svg_hbar(data: list) -> str:
    """Horizontal SVG bar chart.

    Parameters
    ----------
    data : list of (label, value) tuples, sorted descending by value.

    Returns
    -------
    Plain SVG string (no surrounding <div>).
    """
    bar_h = 26
    gap = 7
    label_w = 140
    bar_max = 340
    count_w = 90
    total_w = label_w + bar_max + count_w + 16  # 16px padding

    if not data:
        return '<svg width="1" height="1"></svg>'

    max_val = max(v for _, v in data) or 1
    row_h = bar_h + gap
    svg_h = row_h * len(data) + gap

    rows = []
    for i, (label, value) in enumerate(data):
        colour = _OXIDE_PALETTE[i % len(_OXIDE_PALETTE)]
        y = i * row_h + gap

        # Truncate long labels
        disp_label = label if len(label) <= 18 else label[:17] + "…"
        bar_w = int(bar_max * value / max_val)

        rows.append(
            f'  <!-- {html.escape(label)} -->'
            f'\n  <text x="{label_w - 6}" y="{y + bar_h - 8}"'
            f' text-anchor="end" fill="#2d1a0e" font-size="13" font-family="system-ui,sans-serif"'
            f' font-weight="600">{html.escape(disp_label)}</text>'
            f'\n  <rect x="{label_w}" y="{y}" width="{bar_w}" height="{bar_h}"'
            f' rx="4" fill="{colour}"/>'
            f'\n  <text x="{label_w + bar_w + 8}" y="{y + bar_h - 8}"'
            f' fill="#5a3820" font-size="12" font-family="system-ui,sans-serif"'
            f' font-weight="700">{html.escape(fmt(value))}</text>'
        )

    body = "\n".join(rows)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{svg_h}"'
        f' role="img" aria-label="Language breakdown bar chart">'
        f'\n{body}\n</svg>'
    )


def svg_progress(pct: float, w: int = 300, h: int = 22) -> str:
    """SVG progress bar for a coverage percentage.

    Fill colour:
      >= 70 %  → #2a6846 (green)
      >= 40 %  → #d4851c (amber)
      < 40 %   → #b23030 (red)
    """
    if pct >= 70.0:
        fill = "#2a6846"
    elif pct >= 40.0:
        fill = "#d4851c"
    else:
        fill = "#b23030"

    fill_w = max(0, min(w, int(w * pct / 100)))
    label = f"{pct:.1f}%"

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}"'
        f' role="progressbar" aria-valuenow="{pct:.1f}" aria-valuemin="0" aria-valuemax="100">'
        f'\n  <rect width="{w}" height="{h}" rx="6" fill="#e8ddd8"/>'
        f'\n  <rect width="{fill_w}" height="{h}" rx="6" fill="{fill}"/>'
        f'\n  <text x="{w // 2}" y="{h - 6}" text-anchor="middle"'
        f' fill="#ffffff" font-size="12" font-family="system-ui,sans-serif"'
        f' font-weight="700">{html.escape(label)}</text>'
        f'\n</svg>'
    )


def svg_sparkline(points: list, width: int = 380, height: int = 80) -> str:
    """SVG line sparkline for build-over-build trend data.

    points: list of (build_number, value) pairs, oldest first.
    """
    if len(points) < 2:
        return ""

    values = [v for _, v in points]
    builds = [b for b, _ in points]
    min_v = min(values)
    max_v = max(values)
    value_range = max_v - min_v or 1

    pad_l, pad_r, pad_t, pad_b = 12, 12, 10, 20
    w = width - pad_l - pad_r
    h = height - pad_t - pad_b
    n = len(points)

    def px(i: int, v: int):
        x = pad_l + int(w * i / (n - 1))
        y = pad_t + int(h * (1.0 - (v - min_v) / value_range))
        return x, y

    coords = [px(i, v) for i, v in enumerate(values)]
    path_d = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(coords))
    area_d = (
        path_d
        + f" L{coords[-1][0]},{pad_t + h} L{coords[0][0]},{pad_t + h} Z"
    )

    lx, ly = coords[-1]
    max_i = values.index(max_v)
    min_i = values.index(min_v)
    max_x, max_y = coords[max_i]
    min_x, min_y = coords[min_i]

    extra_dots = ""
    if max_i != n - 1:
        extra_dots += f'\n  <circle cx="{max_x}" cy="{max_y}" r="3" fill="#2a6846" opacity="0.85"/>'
    if min_i != n - 1 and min_i != max_i:
        extra_dots += f'\n  <circle cx="{min_x}" cy="{min_y}" r="3" fill="#b23030" opacity="0.85"/>'

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"'
        f' role="img" aria-label="SLOC trend over last {n} builds">'
        f'\n  <path d="{area_d}" fill="#b04a00" fill-opacity="0.07"/>'
        f'\n  <path d="{path_d}" fill="none" stroke="#b04a00" stroke-width="2"'
        f' stroke-linejoin="round" stroke-linecap="round"/>'
        f'\n  <circle cx="{lx}" cy="{ly}" r="4" fill="#b04a00"/>'
        f"{extra_dots}"
        f'\n  <text x="{pad_l}" y="{height - 3}" font-size="10" fill="#8a6a5a"'
        f' font-family="system-ui,sans-serif">#{html.escape(str(builds[0]))}</text>'
        f'\n  <text x="{width - pad_r}" y="{height - 3}" font-size="10" fill="#8a6a5a"'
        f' text-anchor="end" font-family="system-ui,sans-serif">#{html.escape(str(builds[-1]))}</text>'
        f'\n</svg>'
    )


# ---------------------------------------------------------------------------
# HTML component helpers
# ---------------------------------------------------------------------------

def chip(val_html: str, label: str, sub: Optional[str] = None) -> str:
    """Render a stat chip card.

    Parameters
    ----------
    val_html
        The large value shown at the top.  May contain intentional inline HTML
        such as ``<span style="color:green">OK</span>`` — NOT escaped here.
    label
        Short uppercase label shown below the value.  Will be html-escaped.
    sub
        Optional small supplementary text below the label.  Will be html-escaped.
    """
    sub_html = (
        f'<div class="chip-sub">{html.escape(str(sub))}</div>' if sub is not None else ""
    )
    return (
        f'<div class="stat-chip">'
        f'<div class="stat-chip-val">{val_html}</div>'
        f'<div class="stat-chip-label">{html.escape(str(label))}</div>'
        f'{sub_html}'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Input parsers
# ---------------------------------------------------------------------------

def parse_junit(path: str) -> Optional[dict]:
    """Parse a JUnit XML file.

    Handles both ``<testsuites>`` wrapper root and bare ``<testsuite>`` root.

    Returns a dict with keys: tests, failures, errors, skipped, passed, time.
    Returns None on any error (missing file, parse error, etc.).
    """
    if not os.path.isfile(path):
        return None
    try:
        tree = ET.parse(path)
        root = tree.getroot()

        def _int(el, attr):
            try:
                return int(el.get(attr, 0))
            except (ValueError, TypeError):
                return 0

        def _float(el, attr):
            try:
                return float(el.get(attr, 0.0))
            except (ValueError, TypeError):
                return 0.0

        if root.tag == "testsuites":
            # Aggregate across all <testsuite> children
            tests = failures = errors = skipped = 0
            time_total = 0.0
            for suite in root.findall("testsuite"):
                tests    += _int(suite, "tests")
                failures += _int(suite, "failures")
                errors   += _int(suite, "errors")
                skipped  += _int(suite, "skipped")
                time_total += _float(suite, "time")
        elif root.tag == "testsuite":
            tests    = _int(root, "tests")
            failures = _int(root, "failures")
            errors   = _int(root, "errors")
            skipped  = _int(root, "skipped")
            time_total = _float(root, "time")
        else:
            return None

        passed = max(0, tests - failures - errors - skipped)
        return {
            "tests":    tests,
            "failures": failures,
            "errors":   errors,
            "skipped":  skipped,
            "passed":   passed,
            "time":     time_total,
        }
    except Exception:
        return None


def parse_lcov(path: str) -> tuple:
    """Parse an lcov.info file.

    Accumulates LF: (lines found) and LH: (lines hit) across all source files.

    Returns (hit, found).  Both values are 0 if the file is missing or unreadable.
    """
    if not os.path.isfile(path):
        return (0, 0)
    try:
        hit = 0
        found = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("LF:"):
                    try:
                        found += int(line[3:])
                    except ValueError:
                        pass
                elif line.startswith("LH:"):
                    try:
                        hit += int(line[3:])
                    except ValueError:
                        pass
        return (hit, found)
    except Exception:
        return (0, 0)


def parse_trend_history(path: str) -> list:
    """Parse the persistent per-job trend CSV written by the Jenkinsfile.

    Each row: timestamp, build, code_lines, comment_lines, blank_lines, files_analyzed.
    Returns a list of dicts sorted oldest-first.  Returns [] on any error.
    """
    if not os.path.isfile(path):
        return []
    try:
        rows = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                try:
                    rows.append({
                        "timestamp":      row.get("timestamp", ""),
                        "build":          int(row.get("build", 0)),
                        "code_lines":     int(row.get("code_lines", 0)),
                        "comment_lines":  int(row.get("comment_lines", 0)),
                        "blank_lines":    int(row.get("blank_lines", 0)),
                        "files_analyzed": int(row.get("files_analyzed", 0)),
                    })
                except (ValueError, KeyError):
                    pass
        return rows
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main dashboard generator
# ---------------------------------------------------------------------------

def generate(out_dir: str, slug: Optional[str] = None) -> None:
    """Read CI artifacts from out_dir and write dashboard_<slug>.html."""
    out_dir = os.path.abspath(out_dir)

    # ── Auto-detect slug ────────────────────────────────────────────────────
    if slug is None:
        candidates = glob(os.path.join(out_dir, "result_*.json"))
        if not candidates:
            print(
                f"ERROR: No result_*.json found in {out_dir}. "
                "Pass a project-slug argument or run the SLOC analysis first.",
                file=sys.stderr,
            )
            sys.exit(1)
        candidates.sort()
        basename = os.path.basename(candidates[0])           # result_myproject.json
        slug = basename[len("result_"):-len(".json")]

    # ── Load SLOC JSON ──────────────────────────────────────────────────────
    json_path = os.path.join(out_dir, f"result_{slug}.json")
    if not os.path.isfile(json_path):
        print(
            f"ERROR: {json_path} not found. Run oxide-sloc analyze with --json-out first.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(json_path, encoding="utf-8") as fh:
        data = json.load(fh)

    # oxide-sloc result.json structure:
    #   data["summary_totals"]    → aggregate counts
    #   data["totals_by_language"] → list of per-language dicts
    #       each entry: {"language": str|dict, "code_lines": int, ...}
    totals = data.get("summary_totals", {})
    code_lines     = int(totals.get("code_lines",    0))
    comment_lines  = int(totals.get("comment_lines", 0))
    blank_lines    = int(totals.get("blank_lines",   0))
    files_analyzed = int(totals.get("files_analyzed", 0))

    # Per-language breakdown
    lang_rows = []
    for entry in data.get("totals_by_language", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("language", "Unknown")
        # language field may be a string or a nested object with display_name
        if isinstance(name, dict):
            name = name.get("display_name") or name.get("name") or str(name)
        lang_rows.append((str(name), int(entry.get("code_lines", 0))))

    lang_rows.sort(key=lambda x: x[1], reverse=True)
    top_lang = lang_rows[0][0] if lang_rows else None

    # ── Load test results ───────────────────────────────────────────────────
    junit_path = os.path.join(out_dir, "test-results", "junit.xml")
    junit = parse_junit(junit_path)

    # ── Load coverage ───────────────────────────────────────────────────────
    lcov_path = os.path.join(out_dir, "coverage", "lcov.info")
    cov_hit, cov_found = parse_lcov(lcov_path)
    cov_pct = round(cov_hit / cov_found * 100, 1) if cov_found > 0 else None

    # ── Load trend history ──────────────────────────────────────────────────
    # Path supplied as SLOC_HISTORY_FILE env var (set by Jenkinsfile) or 3rd arg.
    history_file  = os.environ.get("SLOC_HISTORY_FILE", "")
    trend_history = parse_trend_history(history_file) if history_file else []

    # ── Environment ─────────────────────────────────────────────────────────
    build_number = os.environ.get("BUILD_NUMBER", "")
    build_url    = os.environ.get("BUILD_URL", "")
    job_name     = os.environ.get("JOB_NAME", "")
    scan_path    = os.environ.get("SCAN_PATH", "")
    timestamp    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Build chip sections ─────────────────────────────────────────────────

    # SLOC summary chips
    sloc_chips = "".join([
        chip(
            f'<span title="{fmt_full(code_lines)}">{fmt(code_lines)}</span>',
            "Code Lines",
            f"exact: {fmt_full(code_lines)}",
        ),
        chip(
            f'<span title="{fmt_full(comment_lines)}">{fmt(comment_lines)}</span>',
            "Comment Lines",
            f"exact: {fmt_full(comment_lines)}",
        ),
        chip(
            f'<span title="{fmt_full(blank_lines)}">{fmt(blank_lines)}</span>',
            "Blank Lines",
            f"exact: {fmt_full(blank_lines)}",
        ),
        chip(
            f'<span title="{fmt_full(files_analyzed)}">{fmt(files_analyzed)}</span>',
            "Files Analyzed",
            f"top: {top_lang}" if top_lang else None,
        ),
    ])

    # Language chart
    lang_chart = svg_hbar(lang_rows[:20])
    lang_caption = f"{len(lang_rows)} language{'s' if len(lang_rows) != 1 else ''} detected"

    # Test results section
    if junit is not None:
        pass_colour = "#2a6846" if junit["failures"] == 0 and junit["errors"] == 0 else "#b23030"
        status_text = (
            "All tests passed."
            if junit["failures"] == 0 and junit["errors"] == 0
            else f"{junit['failures']} failed, {junit['errors']} error(s)."
        )
        test_chips = "".join([
            chip(fmt(junit["tests"]),    "Total Tests"),
            chip(
                f'<span style="color:{pass_colour}">{fmt(junit["passed"])}</span>',
                "Passed",
            ),
            chip(
                f'<span style="color:#b23030">{fmt(junit["failures"])}</span>',
                "Failed",
            ),
            chip(
                f'<span style="color:#b23030">{fmt(junit["errors"])}</span>',
                "Errors",
            ),
            chip(fmt(junit["skipped"]), "Skipped"),
        ])
        time_str = f"{junit['time']:.2f}s" if junit["time"] > 0 else ""
        test_section = f"""
<div class="card">
  <div class="card-title">Test Results</div>
  <div class="summary-strip summary-strip-5">{test_chips}</div>
  <p class="status-msg" style="color:{pass_colour}">
    {html.escape(status_text)}
    {(' <span class="muted">(' + html.escape(time_str) + ')</span>') if time_str else ''}
  </p>
</div>"""
    else:
        test_section = """
<div class="card">
  <div class="card-title">Test Results</div>
  <p class="muted-msg">JUnit XML not found at <code>test-results/junit.xml</code>.<br>
  Set <code>TEST_RUNNER = cargo-nextest</code> and <code>PUBLISH_TEST_RESULTS = true</code>
  in the pipeline parameters to enable test reporting.</p>
</div>"""

    # Coverage section
    if cov_pct is not None:
        cov_bar = svg_progress(cov_pct)
        coverage_section = f"""
<div class="card">
  <div class="card-title">Code Coverage</div>
  <div class="cov-bar">{cov_bar}</div>
  <p class="cov-detail">
    {html.escape(f"{cov_pct:.1f}%")} line coverage
    &nbsp;&middot;&nbsp;
    {html.escape(fmt_full(cov_hit))} / {html.escape(fmt_full(cov_found))} lines hit
  </p>
</div>"""
    else:
        coverage_section = """
<div class="card">
  <div class="card-title">Code Coverage</div>
  <p class="muted-msg">Coverage data not found at <code>coverage/lcov.info</code>.<br>
  Enable <code>COVERAGE_STANDALONE = true</code> in the pipeline parameters to
  generate LCOV coverage data.</p>
</div>"""

    # ── Trend sparkline section ─────────────────────────────────────────────
    if len(trend_history) >= 2:
        trend_points = [(r["build"], r["code_lines"]) for r in trend_history]
        sparkline    = svg_sparkline(trend_points)
        t_last       = trend_history[-1]
        t_prev       = trend_history[-2]
        delta        = t_last["code_lines"] - t_prev["code_lines"]
        sign         = "+" if delta > 0 else ""
        delta_col    = "#2a6846" if delta > 0 else "#b23030" if delta < 0 else "#8a6a5a"
        n_builds     = len(trend_history)
        trend_section = f"""
<div class="card">
  <div class="card-title">Code Lines Trend &mdash; last {n_builds} build{"s" if n_builds != 1 else ""}</div>
  <div class="sparkline-wrap">
    {sparkline}
  </div>
  <p class="trend-delta" style="color:{delta_col}">
    {html.escape(f"{sign}{fmt(delta)}")} code lines since build #{t_prev["build"]}
    &nbsp;&middot;&nbsp;
    <span style="color:#8a6a5a;font-weight:400">
      range: {html.escape(fmt(min(v for _,v in trend_points)))}
      &ndash; {html.escape(fmt(max(v for _,v in trend_points)))}
    </span>
  </p>
</div>"""
    else:
        trend_section = ""

    # ── Header meta ─────────────────────────────────────────────────────────
    header_meta_parts = []
    if job_name:
        header_meta_parts.append(f"<span>Job: {html.escape(job_name)}</span>")
    if build_number:
        header_meta_parts.append(f"<span>Build #{html.escape(build_number)}</span>")
    if scan_path:
        header_meta_parts.append(f"<span>Scan path: <code>{html.escape(scan_path)}</code></span>")
    header_meta_parts.append(f"<span>{html.escape(timestamp)}</span>")

    back_link = ""
    if build_url:
        back_link = (
            f'<a class="back-link" href="{html.escape(build_url)}">'
            f"&#8592; Back to Jenkins build</a>"
        )

    header_meta_html = " &nbsp;&middot;&nbsp; ".join(header_meta_parts)

    # ── Assemble the full HTML page ─────────────────────────────────────────
    page_title = f"oxide-sloc build dashboard — {slug}"

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(page_title)}</title>
<style>
/* ── Reset & base ──────────────────────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  background: #f9f5f0;
  color: #2d1a0e;
  min-height: 100vh;
}}

/* ── Header ────────────────────────────────────────────────────────────── */
.site-header {{
  background: #2d1a0e;
  color: #f9f5f0;
  padding: 18px 32px 16px;
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 12px 20px;
}}
.site-header .brand {{
  font-size: 22px;
  font-weight: 900;
  color: #e07038;
  letter-spacing: -0.02em;
  white-space: nowrap;
}}
.site-header .dash-title {{
  font-size: 16px;
  font-weight: 700;
  color: #f9f5f0;
  white-space: nowrap;
}}
.site-header .meta {{
  font-size: 12px;
  color: #c8a882;
  flex: 1 1 100%;
  margin-top: 4px;
  display: flex;
  flex-wrap: wrap;
  gap: 0 6px;
  align-items: center;
}}
.site-header .meta code {{
  background: rgba(255,255,255,0.1);
  border-radius: 3px;
  padding: 1px 4px;
  font-size: 11px;
}}
.back-link {{
  display: inline-block;
  margin-left: auto;
  font-size: 12px;
  color: #e07038;
  text-decoration: none;
  border: 1px solid #e07038;
  border-radius: 4px;
  padding: 3px 10px;
  white-space: nowrap;
}}
.back-link:hover {{ background: rgba(224,112,56,0.15); }}

/* ── Main layout ───────────────────────────────────────────────────────── */
.main {{
  max-width: 860px;
  margin: 32px auto;
  padding: 0 20px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}}

/* ── Cards ─────────────────────────────────────────────────────────────── */
.card {{
  background: #fff;
  border: 1px solid #e0d8d0;
  border-radius: 12px;
  padding: 22px 24px;
}}
.card-title {{
  font-size: 13px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #8a6a5a;
  margin-bottom: 16px;
}}

/* ── Stat chips ─────────────────────────────────────────────────────────── */
.summary-strip {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 8px;
}}
.summary-strip-5 {{
  grid-template-columns: repeat(5, 1fr);
}}
.stat-chip {{
  background: #f9f5f0;
  border: 1px solid #e0d8d0;
  border-radius: 12px;
  padding: 14px 16px;
  cursor: default;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}}
.stat-chip:hover {{
  transform: translateY(-3px);
  box-shadow: 0 8px 24px rgba(77,44,20,0.15);
}}
.stat-chip-val {{
  font-size: 20px;
  font-weight: 900;
  color: #b04a00;
}}
.stat-chip-label {{
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: #8a6a5a;
  margin-top: 4px;
}}
.chip-sub {{
  font-size: 11px;
  color: #8a6a5a;
  margin-top: 3px;
}}

/* ── Language chart ─────────────────────────────────────────────────────── */
.lang-chart-wrap {{
  overflow-x: auto;
}}
.lang-caption {{
  font-size: 12px;
  color: #8a6a5a;
  margin-top: 8px;
}}

/* ── Coverage ───────────────────────────────────────────────────────────── */
.cov-bar {{ margin-bottom: 8px; }}
.cov-detail {{
  font-size: 13px;
  color: #5a3820;
  font-weight: 600;
}}

/* ── Status messages ────────────────────────────────────────────────────── */
.status-msg {{
  font-size: 14px;
  font-weight: 700;
  margin-top: 8px;
}}
.muted {{ color: #8a6a5a; font-weight: 400; }}
.muted-msg {{
  color: #8a6a5a;
  font-size: 13px;
  line-height: 1.6;
}}
.muted-msg code {{
  background: #f0e8e0;
  border-radius: 3px;
  padding: 1px 5px;
  font-size: 12px;
}}

/* ── Footer ─────────────────────────────────────────────────────────────── */
.site-footer {{
  text-align: center;
  font-size: 12px;
  color: #8a6a5a;
  padding: 24px 20px 32px;
  border-top: 1px solid #e0d8d0;
  margin-top: 8px;
}}
.site-footer a {{
  color: #b04a00;
  text-decoration: none;
}}
.site-footer a:hover {{ text-decoration: underline; }}

/* ── Trend sparkline ────────────────────────────────────────────────────── */
.sparkline-wrap {{ overflow-x: auto; margin-bottom: 8px; }}
.trend-delta {{ font-size: 13px; font-weight: 700; margin-top: 4px; line-height: 1.5; }}

/* ── Responsive ─────────────────────────────────────────────────────────── */
@media (max-width: 640px) {{
  .summary-strip {{ grid-template-columns: repeat(2, 1fr); }}
  .summary-strip-5 {{ grid-template-columns: repeat(2, 1fr); }}
  .site-header {{ padding: 14px 16px 12px; }}
  .main {{ margin: 16px auto; }}
}}
</style>
</head>
<body>

<!-- ── Header ──────────────────────────────────────────────────────────── -->
<header class="site-header">
  <span class="brand">oxide-sloc</span>
  <span class="dash-title">Build Dashboard &mdash; {html.escape(slug)}</span>
  <div class="meta">
    {header_meta_html}
    {back_link}
  </div>
</header>

<!-- ── Main content ────────────────────────────────────────────────────── -->
<main class="main">

  <!-- SLOC Summary -->
  <div class="card">
    <div class="card-title">SLOC Summary</div>
    <div class="summary-strip">
      {sloc_chips}
    </div>
  </div>

  <!-- Language Breakdown -->
  <div class="card">
    <div class="card-title">Language Breakdown</div>
    <div class="lang-chart-wrap">
      {lang_chart}
    </div>
    <p class="lang-caption">{html.escape(lang_caption)}</p>
  </div>

  <!-- Build Trend -->
  {trend_section}

  <!-- Test Results -->
  {test_section}

  <!-- Code Coverage -->
  {coverage_section}

</main>

<!-- ── Footer ──────────────────────────────────────────────────────────── -->
<footer class="site-footer">
  oxide-sloc build dashboard &nbsp;&middot;&nbsp;
  generated {html.escape(timestamp)} &nbsp;&middot;&nbsp;
  <a href="https://github.com/oxide-sloc/oxide-sloc" target="_blank" rel="noopener">
    oxide-sloc on GitHub
  </a>
</footer>

</body>
</html>
"""

    # ── Write output file ───────────────────────────────────────────────────
    out_path = os.path.join(out_dir, f"dashboard_{slug}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html_out)

    print(out_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: python3 ci/jenkins/generate-dashboard.py <output-dir> [project-slug] [history-file]",
            file=sys.stderr,
        )
        sys.exit(1)

    out_dir = sys.argv[1]
    slug    = sys.argv[2] if len(sys.argv) >= 3 else None

    # 3rd arg overrides SLOC_HISTORY_FILE env var
    if len(sys.argv) >= 4 and sys.argv[3]:
        os.environ["SLOC_HISTORY_FILE"] = sys.argv[3]

    if not os.path.isdir(out_dir):
        print(f"ERROR: output directory does not exist: {out_dir}", file=sys.stderr)
        sys.exit(1)

    generate(out_dir, slug)


if __name__ == "__main__":
    main()
