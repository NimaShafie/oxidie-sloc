# Roadmap

This is the near-term roadmap for oxide-sloc. Items are roughly priority-ordered within each
section. Completed work ships as patch or minor releases; breaking changes target the next minor.

## In progress

- **PDF generation in web UI** — PDF export is fully functional via CLI (`--pdf-out`); the web UI
  currently defers it. Completing the async job plumbing will close the gap.

## Planned

- **tree-sitter adapters** — Replace the hand-rolled lexical state machines for Python and C/C++
  with tree-sitter grammars for more accurate comment / code classification, especially for
  nested constructs and multi-line strings.

- **Validation corpus + golden tests** — A set of canonical source files with known line counts
  to lock the counting logic against regressions as new languages or policy options are added.

- **IEEE 1045-1992 parameters in web UI** — Continuation-line policy, blank-in-block-comment
  policy, and compiler-directive exclusion are currently CLI/config only. The step-2 form will
  expose them with inline explanations.

- **`validate` command** — `oxide-sloc validate <result.json>` re-counts from the original files
  and reports any drift, useful for auditing saved results against a live checkout.

- **Git-triggered scan registration** — Scans triggered via webhook or polling currently do not
  appear in `/view-reports`. Registering them in `AppState.registry` will make the full history
  visible from the web UI.

## Ideas / under consideration

- Silver / Gold OpenSSF Best Practices badge criteria
- WASM build target for browser-native analysis
- Language Server Protocol (LSP) integration for IDE inline metrics
- Plugin API for custom language analyzers

---

Issues and discussion: <https://github.com/oxide-sloc/oxide-sloc/issues>
