#!/usr/bin/env python3
"""Parse an lcov.info file and print a per-file coverage summary table."""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class FileCoverage:
    path: str
    lines_found: int = 0
    lines_hit: int = 0
    branches_found: int = 0
    branches_hit: int = 0
    funcs_found: int = 0
    funcs_hit: int = 0

    @property
    def line_pct(self) -> float:
        """Percentage of instrumented lines that were executed."""
        if self.lines_found == 0:
            return 0.0
        return self.lines_hit / self.lines_found * 100.0

    @property
    def branch_pct(self) -> float:
        """Percentage of branches that were taken."""
        if self.branches_found == 0:
            return 0.0
        return self.branches_hit / self.branches_found * 100.0

    @property
    def func_pct(self) -> float:
        """Percentage of functions that were called."""
        if self.funcs_found == 0:
            return 0.0
        return self.funcs_hit / self.funcs_found * 100.0


def parse_lcov(path: Path) -> Dict[str, FileCoverage]:
    """Read an lcov.info file and return a dict keyed by source-file path."""
    records: Dict[str, FileCoverage] = {}
    current: Optional[FileCoverage] = None

    for raw in path.read_text(encoding="utf-8").splitlines():
        tag, _, value = raw.partition(":")
        tag = tag.strip()

        if tag == "SF":
            current = FileCoverage(path=value.strip())
        elif current is None:
            continue
        elif tag == "LF":
            current.lines_found = int(value)
        elif tag == "LH":
            current.lines_hit = int(value)
        elif tag == "BRF":
            current.branches_found = int(value)
        elif tag == "BRH":
            current.branches_hit = int(value)
        elif tag == "FNF":
            current.funcs_found = int(value)
        elif tag == "FNH":
            current.funcs_hit = int(value)
        elif tag == "end_of_record":
            records[current.path] = current
            current = None

    return records


def colour(pct: float) -> str:
    """ANSI colour code based on coverage percentage."""
    if pct >= 90.0:
        return "\033[32m"   # green
    if pct >= 75.0:
        return "\033[33m"   # yellow
    return "\033[31m"       # red


RESET = "\033[0m"
HDR = f"{'File':<38} {'Lines':>9}  {'Cov%':>6}  {'Branches':>10}  {'Funcs':>8}"
SEP = "-" * 76


def print_summary(records: Dict[str, FileCoverage], use_colour: bool = True) -> None:
    total_lf = total_lh = total_brf = total_brh = total_ff = total_fh = 0

    print(f"\n{HDR}")
    print(SEP)

    for cov in sorted(records.values(), key=lambda c: c.path):
        name = Path(cov.path).name
        c = colour(cov.line_pct) if use_colour else ""
        r = RESET if use_colour else ""
        print(
            f"{name:<38} {cov.lines_hit:>4}/{cov.lines_found:<4}"
            f"  {c}{cov.line_pct:>5.1f}%{r}"
            f"  {cov.branches_hit:>4}/{cov.branches_found:<4}"
            f"  {cov.funcs_hit:>2}/{cov.funcs_found}"
        )
        total_lf += cov.lines_found
        total_lh += cov.lines_hit
        total_brf += cov.branches_found
        total_brh += cov.branches_hit
        total_ff += cov.funcs_found
        total_fh += cov.funcs_hit

    print(SEP)
    line_pct = (total_lh / total_lf * 100) if total_lf else 0.0
    br_pct = (total_brh / total_brf * 100) if total_brf else 0.0
    c = colour(line_pct) if use_colour else ""
    r = RESET if use_colour else ""
    print(
        f"{'TOTAL':<38} {total_lh:>4}/{total_lf:<4}"
        f"  {c}{line_pct:>5.1f}%{r}"
        f"  {total_brh:>4}/{total_brf:<4}"
        f"  {total_fh:>2}/{total_ff}"
    )
    print(f"\nBranch coverage: {br_pct:.1f}%\n")


if __name__ == "__main__":
    lcov_file = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("coverage/lcov.info")
    use_colour = sys.stdout.isatty()

    if not lcov_file.exists():
        print(f"error: {lcov_file} not found", file=sys.stderr)
        sys.exit(1)

    recs = parse_lcov(lcov_file)
    print_summary(recs, use_colour=use_colour)
