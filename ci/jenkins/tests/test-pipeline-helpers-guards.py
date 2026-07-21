#!/usr/bin/env python3
"""Static guard tests for ci/jenkins/pipeline-helpers.groovy.

These lock in fixes that are invisible to a compiler and easy to silently
regress during unrelated edits:

  P0: the bitbucketStatusNotify(...) call MUST be wrapped in `catch (Throwable ...)`,
      not `catch (Exception ...)` / an untyped `catch (e)`. When the
      bitbucket-build-status-notifier plugin is absent, Pipeline throws
      java.lang.NoSuchMethodError — a java.lang.Error, not an Exception — so an
      Exception-typed catch lets it escape, aborts post{always}, and skips the
      plugin-independent REST fallback (breaking the no-admin / Tier-3 path).

  P3: the bitbucketStatusNotify(...) call MUST NOT pass a buildUrl: argument (the
      installed plugin version rejects it with an "Unknown parameter" warning).

Run:  python3 ci/jenkins/tests/test-pipeline-helpers-guards.py
Exit code 0 = all guards hold.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HELPERS = os.path.abspath(os.path.join(HERE, "..", "pipeline-helpers.groovy"))

RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))


def main() -> None:
    with open(HELPERS, encoding="utf-8") as fh:
        src = fh.read()

    # Locate the bitbucketStatusNotify(...) call and the catch clause that
    # immediately follows its closing paren.
    call_idx = src.find("bitbucketStatusNotify(")
    check("bitbucketStatusNotify call present", call_idx != -1)

    if call_idx != -1:
        # The try/catch wrapping the call: find the next `} catch (...)` after it.
        tail = src[call_idx:call_idx + 1200]
        m = re.search(r"\}\s*catch\s*\(([^)]*)\)", tail)
        catch_arg = m.group(1) if m else ""
        check("P0: bitbucketStatusNotify wrapped in catch (Throwable ...)",
              "Throwable" in catch_arg,
              f"catch arg was: {catch_arg!r}")

        # The call args (between the first '(' and its matching close before the
        # catch) must not contain a buildUrl: parameter.
        call_block = tail.split("} catch", 1)[0]
        check("P3: no buildUrl: argument on bitbucketStatusNotify",
              "buildUrl" not in call_block,
              "buildUrl: still present in the plugin call")

    print("=" * 78)
    print("pipeline-helpers.groovy — static guard tests")
    print("=" * 78)
    all_ok = True
    for name, ok, detail in RESULTS:
        all_ok = all_ok and ok
        line = f"[{'PASS' if ok else 'FAIL'}] {name}"
        if not ok and detail:
            line += f"\n        {detail}"
        print(line)
    print("-" * 78)
    print("OVERALL:", "ALL PASSED" if all_ok else "SOME FAILED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
