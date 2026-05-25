"""oxide-sloc CI build dashboard generator.

Reads CI output artifacts from <output-dir> and writes a single self-contained
HTML file with inline SVG charts and CSS.  Requires only Python 3 standard library —
no pip installs, no external JS libraries, and no Jenkins plugins beyond the core
``archiveArtifacts`` step.

Usage
-----
    python3 ci/jenkins/generate-dashboard.py <output-dir> [project-slug] [history-file]

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
import re
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
    lang_rows = []        # (name, code_lines) for bar chart
    lang_table_rows = []  # full row dicts for table
    for entry in data.get("totals_by_language", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("language", "Unknown")
        if isinstance(name, dict):
            name = name.get("display_name") or name.get("name") or str(name)
        code = int(entry.get("code_lines", 0))
        lang_rows.append((str(name), code))
        lang_table_rows.append({
            "name":           str(name),
            "code_lines":     code,
            "comment_lines":  int(entry.get("comment_lines", 0)),
            "blank_lines":    int(entry.get("blank_lines",   0)),
            "files_analyzed": int(entry.get("files_analyzed", 0)),
        })

    lang_rows.sort(key=lambda x: x[1], reverse=True)
    lang_table_rows.sort(key=lambda x: x["code_lines"], reverse=True)
    top_lang = lang_rows[0][0] if lang_rows else None

    # Top files by code lines
    top_files = []
    for rec in data.get("per_file_records", []):
        if not isinstance(rec, dict):
            continue
        lang = rec.get("language", "")
        if isinstance(lang, dict):
            lang = lang.get("display_name") or lang.get("name") or str(lang)
        top_files.append({
            "path":       str(rec.get("path", "")),
            "language":   str(lang),
            "code_lines": int(rec.get("code_lines", 0)),
        })
    top_files.sort(key=lambda x: x["code_lines"], reverse=True)
    top_files = top_files[:20]

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

    # Delta from previous build (requires trend history with >= 2 entries)
    delta_chip_html = ""
    if len(trend_history) >= 2:
        t_prev_build = trend_history[-2]
        delta = code_lines - t_prev_build["code_lines"]
        sign = "+" if delta > 0 else ""
        delta_col = "#2a6846" if delta > 0 else "#b23030" if delta < 0 else "#8a6a5a"
        delta_chip_html = chip(
            f'<span style="color:{delta_col}" title="vs build #{t_prev_build["build"]}">'
            f"{sign}{fmt(delta)}</span>",
            "Code Lines Δ",
            f"vs build #{t_prev_build['build']}",
        )

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
        delta_chip_html,
    ])
    sloc_strip_class = "summary-strip summary-strip-5" if delta_chip_html else "summary-strip"

    # Language chart
    lang_chart = svg_hbar(lang_rows[:20])
    lang_caption = f"{len(lang_rows)} language{'s' if len(lang_rows) != 1 else ''} detected"

    # Per-language metrics table
    if lang_table_rows:
        _tbl_rows = "\n".join(
            f"<tr>"
            f"<td>{html.escape(r['name'])}</td>"
            f"<td class='num'>{fmt(r['code_lines'])}</td>"
            f"<td class='num'>{fmt(r['comment_lines'])}</td>"
            f"<td class='num'>{fmt(r['blank_lines'])}</td>"
            f"<td class='num'>{fmt(r['files_analyzed'])}</td>"
            f"</tr>"
            for r in lang_table_rows
        )
        lang_table_html = f"""
<table class="data-table" style="margin-top:18px">
  <thead>
    <tr>
      <th>Language</th>
      <th class="num">Code</th>
      <th class="num">Comments</th>
      <th class="num">Blank</th>
      <th class="num">Files</th>
    </tr>
  </thead>
  <tbody>
    {_tbl_rows}
  </tbody>
</table>"""
    else:
        lang_table_html = ""

    # Top files section
    if top_files:
        _file_rows = "\n".join(
            f"<tr>"
            f'<td class="trunc" title="{html.escape(f["path"])}">{html.escape(f["path"])}</td>'
            f"<td>{html.escape(f['language'])}</td>"
            f"<td class='num'>{fmt(f['code_lines'])}</td>"
            f"</tr>"
            for f in top_files
        )
        files_section = f"""
<div class="card">
  <div class="card-title">Top Files by Code Lines</div>
  <table class="data-table">
    <thead>
      <tr>
        <th>Path</th>
        <th>Language</th>
        <th class="num">Code Lines</th>
      </tr>
    </thead>
    <tbody>
      {_file_rows}
    </tbody>
  </table>
</div>"""
    else:
        files_section = ""

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
        t_last_h     = trend_history[-1]
        t_prev_h     = trend_history[-2]
        tr_delta     = t_last_h["code_lines"] - t_prev_h["code_lines"]
        tr_sign      = "+" if tr_delta > 0 else ""
        tr_col       = "#2a6846" if tr_delta > 0 else "#b23030" if tr_delta < 0 else "#8a6a5a"
        n_builds     = len(trend_history)
        trend_section = f"""
<div class="card">
  <div class="card-title">Code Lines Trend &mdash; last {n_builds} build{"s" if n_builds != 1 else ""}</div>
  <div class="sparkline-wrap">
    {sparkline}
  </div>
  <p class="trend-delta" style="color:{tr_col}">
    {html.escape(f"{tr_sign}{fmt(tr_delta)}")} code lines since build #{t_prev_h["build"]}
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

    header_meta_html = "".join(header_meta_parts)

    # ── Assemble the full HTML page ─────────────────────────────────────────
    page_title = f"oxide-sloc Graphical Report — {slug}"

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
  background: linear-gradient(180deg, #3a2010 0%, #2d1a0e 100%);
  border-bottom: 2px solid rgba(224,112,56,0.55);
  box-shadow: 0 4px 22px rgba(0,0,0,0.38);
  color: #f9f5f0;
  padding: 0 32px;
}}
.site-header-row {{
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 0 10px;
  flex-wrap: nowrap;
}}
.site-header .brand {{
  font-size: 21px;
  font-weight: 900;
  color: #e07038;
  letter-spacing: -0.02em;
  white-space: nowrap;
  flex-shrink: 0;
  text-shadow: 0 0 20px rgba(224,112,56,0.4);
}}
.header-div {{
  width: 1px;
  height: 22px;
  background: rgba(255,255,255,0.22);
  flex-shrink: 0;
}}
.site-header .dash-title {{
  font-size: 15px;
  font-weight: 600;
  color: rgba(249,245,240,0.88);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}}
.header-fill {{ flex: 1; }}
.site-header .meta {{
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  padding-bottom: 12px;
}}
.site-header .meta > span {{
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.14);
  border-radius: 20px;
  padding: 3px 11px;
  font-size: 11px;
  color: #c8a882;
  white-space: nowrap;
}}
.site-header .meta code {{
  background: rgba(255,255,255,0.12);
  border-radius: 3px;
  padding: 1px 5px;
  font-size: 10px;
  color: #d4a060;
  font-family: ui-monospace, "Cascadia Code", monospace;
}}
.back-link {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(224,112,56,0.18);
  border: 1px solid rgba(224,112,56,0.5);
  border-radius: 8px;
  padding: 7px 16px;
  color: #f09060;
  text-decoration: none;
  font-size: 13px;
  font-weight: 700;
  white-space: nowrap;
  flex-shrink: 0;
  transition: background 0.18s ease, box-shadow 0.18s ease;
}}
.back-link:hover {{
  background: rgba(224,112,56,0.32);
  box-shadow: 0 0 14px rgba(224,112,56,0.28);
}}

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

/* ── Data tables ─────────────────────────────────────────────────────────── */
.data-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}}
.data-table th {{
  text-align: left;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: #8a6a5a;
  padding: 6px 10px 8px;
  border-bottom: 2px solid #e0d8d0;
}}
.data-table td {{
  padding: 7px 10px;
  border-bottom: 1px solid #f0e8e0;
  color: #2d1a0e;
}}
.data-table tr:last-child td {{ border-bottom: none; }}
.data-table .num {{
  text-align: right;
  font-variant-numeric: tabular-nums;
  font-weight: 600;
}}
.data-table .trunc {{
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}

/* ── Responsive ─────────────────────────────────────────────────────────── */
@media (max-width: 640px) {{
  .summary-strip {{ grid-template-columns: repeat(2, 1fr); }}
  .summary-strip-5 {{ grid-template-columns: repeat(2, 1fr); }}
  .site-header {{ padding: 0 16px; }}
  .site-header-row {{ padding: 12px 0 8px; gap: 10px; }}
  .site-header .meta {{ padding-bottom: 10px; }}
  .main {{ margin: 16px auto; }}
}}
</style>
</head>
<body>

<!-- ── Header ──────────────────────────────────────────────────────────── -->
<header class="site-header">
  <div class="site-header-row">
    <span class="brand">oxide-sloc</span>
    <span class="header-div"></span>
    <span class="dash-title">Graphical Report &mdash; {html.escape(slug)}</span>
    <div class="header-fill"></div>
    {back_link}
  </div>
  <div class="meta">
    {header_meta_html}
  </div>
</header>

<!-- ── Main content ────────────────────────────────────────────────────── -->
<main class="main">

  <!-- SLOC Summary (code lines + delta when trend history available) -->
  <div class="card">
    <div class="card-title">SLOC Summary</div>
    <div class="{sloc_strip_class}">
      {sloc_chips}
    </div>
  </div>

  <!-- Build Trend (shown before language breakdown so the delta is prominent) -->
  {trend_section}

  <!-- Language Breakdown -->
  <div class="card">
    <div class="card-title">Language Breakdown</div>
    <div class="lang-chart-wrap">
      {lang_chart}
    </div>
    <p class="lang-caption">{html.escape(lang_caption)}</p>
    {lang_table_html}
  </div>

  <!-- Top Files -->
  {files_section}

  <!-- Test Results -->
  {test_section}

  <!-- Code Coverage -->
  {coverage_section}

</main>

<!-- ── Footer ──────────────────────────────────────────────────────────── -->
<footer class="site-footer">
  oxide-sloc Graphical Report &nbsp;&middot;&nbsp;
  generated {html.escape(timestamp)} &nbsp;&middot;&nbsp;
  <a href="https://github.com/oxide-sloc/oxide-sloc" target="_blank" rel="noopener">
    oxide-sloc on GitHub
  </a>
</footer>

</body>
</html>
"""

    # ── Extract inline CSS to external file (Jenkins CSP fix) ──────────────
    # Jenkins's default artifact-viewer CSP blocks <style> tags but permits
    # external stylesheets from 'self'.  Writing the CSS to a separate file
    # and referencing it via <link> means the report renders correctly without
    # requiring credentials or a custom init.groovy.d CSP override.
    css_match = re.search(r"<style>([\s\S]*?)</style>", html_out)
    if css_match:
        css_filename = f"dashboard_{slug}.css"
        css_path = os.path.join(out_dir, css_filename)
        with open(css_path, "w", encoding="utf-8") as fh:
            fh.write(css_match.group(1))
        html_out = html_out.replace(
            css_match.group(0),
            f'<link rel="stylesheet" href="{css_filename}">',
            1,
        )

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
