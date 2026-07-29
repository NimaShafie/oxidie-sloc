#!/usr/bin/env python3
"""Regression coverage for ci/lint-pipeline-shell.py (the status-masking pipe guard).

Uses embedded string fixtures rather than `git show <sha>:…` so it works in the
shallow clones used by the GitLab lint job / gitlab-ci-local, where historical
revisions are often unreachable (a history-dependent test would fail for the
wrong reason). Asserts:
  - the three historical defects are flagged (D1 |tail returnStatus, D2 bare |tee,
    D3 bare |tail),
  - a bash + pipefail step piping into tee is exempt,
  - rule 2 fires on `set -o pipefail` in a non-bash step and stays quiet with a
    bash shebang,
  - rule 3 fires on a ci .sh without pipefail, and
  - a pipe inside `$( … )` under returnStdout is NOT flagged.

This tests guard BEHAVIOUR against embedded fixtures only. It deliberately does
NOT assert the live repo is clean — that is the scan's job, and the scan prints
the offending file:line + rule. (If the self-test owned that assertion, a real bad
pipe would fail the self-test and the wrapper's `set -e` would abort before the
scan ran, hiding the actionable finding behind a misleading "self-test failed".)

Run: `python3 ci/lint-pipeline-shell-test.py`  →  exit 0 all-pass / 1 on regression.
The wrapper (ci/lint-pipeline-shell.sh) runs this before the repo scan, so every
CI lint invocation re-verifies the guard itself.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("pipeguard", HERE / "lint-pipeline-shell.py")
G = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(G)


def _groovy(src: str):
    out: list = []
    G.check_groovy("<fixture>", src, out)
    return out


def _shell(src: str):
    out: list = []
    G.check_shell("<fixture>", src, out)
    return out


def _rules(findings):
    return sorted(r for _, _, r, _ in findings)


# ── historical defects (must all be rule-1 flagged) ──────────────────────────
D1 = (
    "node {\n"
    "  def x = sh(script: 'cargo install --offline cargo-nextest 2>&1 | tail -5',\n"
    "             returnStatus: true) == 0\n"
    "}\n"
)
D2 = (
    "node {\n"
    '  sh """\n'
    "    cargo nextest run --workspace --profile ci \\\n"
    "        2>&1 | tee '/tmp/out.txt'\n"
    '  """\n'
    "}\n"
)
D3 = (
    "node {\n"
    '  sh """\n'
    "    genhtml x --output-directory y \\\n"
    "        2>&1 | tail -20\n"
    '  """\n'
    "}\n"
)

# bash + pipefail piping into tee → exempt (the surviving, correct form)
EXEMPT = (
    "node {\n"
    '  def s = sh(script: """#!/bin/bash\n'
    "    set -o pipefail\n"
    "    cargo nextest run | tee '/tmp/out.txt'\n"
    '  """, returnStatus: true)\n'
    "}\n"
)

# rule 2: `set -o pipefail` in a step with no bash shebang (dash aborts)
R2_BAD = 'node {\n  sh(script: """set -o pipefail\n    make x""", returnStatus: true)\n}\n'
R2_OK = EXEMPT  # bash shebang + pipefail → no rule-2

# false positive guard: the only pipe is inside $( … ) under returnStdout
FP = (
    "node {\n"
    '  def p = sh(script: """\n'
    "    T=$(grep -E '^LF:' f | awk -F: '{s+=$2} END{print s+0}')\n"
    '    [ "$T" -gt 0 ] && echo "$T" || echo "N/A"\n'
    '  """, returnStdout: true).trim()\n'
    "}\n"
)

# rule 3: ci shell script fixtures
R3_BAD = "#!/usr/bin/env bash\nset -eu\necho hi\n"
R3_OK = "#!/usr/bin/env bash\nset -euo pipefail\necho hi\n"


CHECKS = [
    ("D1  |tail under returnStatus flagged", lambda: 1 in _rules(_groovy(D1))),
    ("D2  bare |tee flagged (the dangerous gap)", lambda: 1 in _rules(_groovy(D2))),
    ("D3  bare |tail flagged", lambda: 1 in _rules(_groovy(D3))),
    ("bash+pipefail |tee is exempt", lambda: _groovy(EXEMPT) == []),
    ("rule 2 flags pipefail in non-bash step", lambda: 2 in _rules(_groovy(R2_BAD))),
    ("rule 2 quiet with bash shebang", lambda: 2 not in _rules(_groovy(R2_OK))),
    ("rule 3 flags ci .sh without pipefail", lambda: 3 in _rules(_shell(R3_BAD))),
    ("rule 3 quiet with pipefail", lambda: _shell(R3_OK) == []),
    ("$( ... | ... ) under returnStdout not flagged", lambda: _groovy(FP) == []),
]


def main() -> int:
    failed = []
    for name, thunk in CHECKS:
        try:
            ok = bool(thunk())
        except Exception as exc:  # a fixture that errors is a failure, not a crash
            ok = False
            name = f"{name}  [raised {exc!r}]"
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failed.append(name)
    if failed:
        passed = len(CHECKS) - len(failed)
        print(f"\nself-test: {passed}/{len(CHECKS)} passed, {len(failed)} FAILED",
              file=sys.stderr)
        return 1
    print(f"self-test: {len(CHECKS)}/{len(CHECKS)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
