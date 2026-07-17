#!/usr/bin/env python3
"""Convert an oxide-sloc result.json into SARIF 2.1.0 for GitHub code scanning.

Surfaces two actionable, per-file signals oxide-sloc already computes:

  * high cyclomatic complexity  → warning (>= warn) / note (>= note)
  * large-file hotspots         → note (code_lines >= hotspot threshold)

so they show up inline in the PR "Files changed" tab via upload-sarif. Standard
library only.

Usage:
    python3 ci/github/sloc-to-sarif.py <result.json> <out.sarif> \
        [--cc-warn 50] [--cc-note 25] [--hotspot 800]
"""

import json
import sys

TOOL = {
    "driver": {
        "name": "oxide-sloc",
        "informationUri": "https://github.com/oxide-sloc/oxide-sloc",
        "rules": [
            {
                "id": "high-cyclomatic-complexity",
                "name": "HighCyclomaticComplexity",
                "shortDescription": {"text": "High cyclomatic complexity"},
                "fullDescription": {"text":
                    "This file has a high approximate cyclomatic complexity "
                    "(sum of branch-decision keywords). Consider splitting it."},
                "defaultConfiguration": {"level": "warning"},
                "helpUri": "https://en.wikipedia.org/wiki/Cyclomatic_complexity",
            },
            {
                "id": "large-file-hotspot",
                "name": "LargeFileHotspot",
                "shortDescription": {"text": "Large source file"},
                "fullDescription": {"text":
                    "This file is unusually large (code lines). Large files are "
                    "harder to review and maintain."},
                "defaultConfiguration": {"level": "note"},
            },
        ],
    }
}


def _arg(flag, default):
    if flag in sys.argv:
        try:
            return int(sys.argv[sys.argv.index(flag) + 1])
        except (ValueError, IndexError):
            return default
    return default


def _result(rule_id, level, uri, message):
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": 1},
            }
        }],
        # Stable fingerprint so GitHub dedupes the finding across runs.
        "partialFingerprints": {"oxideSlocFinding": f"{rule_id}:{uri}"},
    }


def main() -> None:
    if len(sys.argv) < 3:
        sys.stderr.write("usage: sloc-to-sarif.py <result.json> <out.sarif>\n")
        sys.exit(2)
    src, dst = sys.argv[1], sys.argv[2]
    cc_warn = _arg("--cc-warn", 50)
    cc_note = _arg("--cc-note", 25)
    hotspot = _arg("--hotspot", 800)

    with open(src, encoding="utf-8") as fh:
        data = json.load(fh)

    results = []
    for rec in data.get("per_file_records", []):
        if not isinstance(rec, dict):
            continue
        uri = rec.get("relative_path") or rec.get("path") or ""
        if not uri:
            continue
        cc = rec.get("cyclomatic_complexity")
        if isinstance(cc, int):
            if cc >= cc_warn:
                results.append(_result(
                    "high-cyclomatic-complexity", "warning", uri,
                    f"Cyclomatic complexity ~{cc} (threshold {cc_warn}). "
                    "Consider refactoring into smaller units."))
            elif cc >= cc_note:
                results.append(_result(
                    "high-cyclomatic-complexity", "note", uri,
                    f"Cyclomatic complexity ~{cc} (threshold {cc_note})."))
        code = (rec.get("effective_counts") or {}).get("code_lines", 0)
        if isinstance(code, int) and code >= hotspot:
            results.append(_result(
                "large-file-hotspot", "note", uri,
                f"{code:,} code lines (hotspot threshold {hotspot:,})."))

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": TOOL, "results": results}],
    }
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    print(f"sloc-to-sarif: wrote {len(results)} finding(s) to {dst}")


if __name__ == "__main__":
    main()
