#!/usr/bin/env bash
# =============================================================================
# purge-git-history.sh — shrink .git by purging superseded large binary blobs
# =============================================================================
#
# WHY THIS EXISTS
#   oxide-sloc commits its offline-build payload directly to git (vendor.tar.xz,
#   the split Rust toolchain archives, dist release binaries). Every dependency
#   bump re-commits vendor.tar.xz (~65 MB) and every Rust version bump re-commits
#   the toolchain (~590 MB). Old copies accumulate in history forever, so .git
#   grows without bound. This was first cleaned on 2026-07-03 (3.66 GiB -> 688 MiB).
#   This script codifies that exact procedure so future re-purges are one command.
#
# WHAT IT DOES
#   Removes ONLY superseded *historical* copies of the large archives. The current
#   versions are re-added unchanged at HEAD, so a fresh clone still builds fully
#   offline (the air-gap guarantee is preserved). It does NOT touch source history.
#
# THE COST (unavoidable — this rewrites history)
#   Every commit SHA changes; requires a force-push of main + all tags. Old commit
#   permalinks 404, past build-provenance attestations orphan, anyone with a clone
#   must re-clone. GitHub Releases survive (assets are stored separately by tag name).
#
# USAGE
#   bash scripts/internal/purge-git-history.sh            # backup + rewrite + verify
#                                                         # (LOCAL ONLY — stops before push)
#   bash scripts/internal/purge-git-history.sh --push     # also do the guarded force-push
#                                                         # + sync this working repo
#
# REQUIREMENTS: git, git-filter-repo, gh (authenticated) for --push.
# SAFE TO RE-RUN. Without --push, nothing on the remote or in this working repo
# changes — everything happens in a throwaway clone and a backup dir.
# =============================================================================
set -euo pipefail

# ---- config -----------------------------------------------------------------
REPO_SLUG="oxide-sloc/oxide-sloc"
# Paths whose *entire history* is stripped. Current HEAD copies of RE-ADD paths
# are restored after the strip so the offline build still works.
STRIP_PATHS=( vendor.tar.xz vendor.tar.xz.sha256 )
STRIP_GLOBS=( 'toolchain/rust-toolchain-*' )
STRIP_DIRS=( vendor/ dist/ )          # vendor/ is purged entirely (gitignored at HEAD)
# Paths to copy from current HEAD and re-add after the rewrite (must build offline):
READD_FILES=( vendor.tar.xz vendor.tar.xz.sha256 )
READD_GLOBS=( 'toolchain/rust-toolchain-*' )     # toolchain/checksums.sha256 is NOT stripped
READD_DIR_FILES=( 'dist/*' )          # whatever dist files are tracked at HEAD
# Workflows that fire on tag/any push — disabled during the tag force-push:
STORM_WORKFLOWS=( release.yml docker.yml codeql.yml )
# -----------------------------------------------------------------------------

PUSH=0
[[ "${1:-}" == "--push" ]] && PUSH=1

log()  { printf '\n\033[1;36m==>\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v git-filter-repo >/dev/null 2>&1 || die "git-filter-repo not installed (pip install git-filter-repo)"
REPO_ROOT="$(git rev-parse --show-toplevel)" || die "not in a git repo"
cd "$REPO_ROOT"
ORIGIN_URL="$(git remote get-url origin)"
BK="${HOME}/oxide-sloc-backups/$(date +%F_%H%M%S)"
TMP="$(mktemp -d -t oxide-purge-XXXX)/clone"

# ---- preconditions ----------------------------------------------------------
log "Preconditions"
[[ -z "$(git status --porcelain)" ]] || die "working tree not clean — commit/stash first"
git fetch origin --quiet
LOCAL="$(git rev-parse @)"; REMOTE="$(git rev-parse @{u} 2>/dev/null || echo none)"
[[ "$LOCAL" == "$REMOTE" ]] || die "local main not in sync with origin — reconcile first"
echo "  origin: $ORIGIN_URL"
echo "  backups dir: $BK"
echo "  .git size before: $(git count-objects -vH | awk '/size-pack/{print $2,$3}')"

# ---- Phase 0: backups -------------------------------------------------------
log "Phase 0 — backups (bundle + stashes + HEAD assets)"
mkdir -p "$BK/head-assets"
git bundle create "$BK/full.bundle" --all >/dev/null
git bundle verify "$BK/full.bundle" >/dev/null && echo "  full.bundle OK"
# stashes (best-effort): patches + a bundle of stash refs
n=0; while git rev-parse "stash@{$n}" >/dev/null 2>&1; do
  git stash show -p --binary "stash@{$n}" > "$BK/stash-$n.patch" || true
  git branch "backup/stash-$n" "stash@{$n}" >/dev/null 2>&1 || true
  n=$((n+1))
done
[[ $n -gt 0 ]] && { git bundle create "$BK/stashes.bundle" $(git branch --list 'backup/stash-*' | tr -d ' ') >/dev/null 2>&1 || true; echo "  backed up $n stash(es)"; }
# current HEAD assets to re-add after the rewrite
for f in "${READD_FILES[@]}"; do [[ -e "$f" ]] && cp "$f" "$BK/head-assets/"; done
for g in "${READD_GLOBS[@]}"; do cp $g "$BK/head-assets/" 2>/dev/null || true; done
mkdir -p "$BK/head-assets/dist"; for g in "${READD_DIR_FILES[@]}"; do cp $g "$BK/head-assets/dist/" 2>/dev/null || true; done
( cd "$BK/head-assets" && sha256sum -c vendor.tar.xz.sha256 >/dev/null && echo "  head-assets checksum OK" )

# ---- Phase 1: rewrite on a throwaway clone ----------------------------------
log "Phase 1 — filter-repo on a throwaway clone (working repo untouched)"
git clone --no-local "$REPO_ROOT" "$TMP" >/dev/null 2>&1
cd "$TMP"
git remote remove origin                      # drop backup/stash-* tracking refs
fr_args=( --force --prune-empty never --invert-paths )
for p in "${STRIP_PATHS[@]}"; do fr_args+=( --path "$p" ); done
for d in "${STRIP_DIRS[@]}";  do fr_args+=( --path "$d" ); done
for g in "${STRIP_GLOBS[@]}"; do fr_args+=( --path-glob "$g" ); done
git filter-repo "${fr_args[@]}"
# re-add current assets at HEAD
cp "$BK/head-assets/"*.tar.xz "$BK/head-assets/"*.sha256 . 2>/dev/null || true
mkdir -p toolchain dist
cp "$BK"/head-assets/rust-toolchain-* toolchain/ 2>/dev/null || true
cp "$BK"/head-assets/dist/* dist/ 2>/dev/null || true
git add -f "${READD_FILES[@]}" toolchain/ dist/ 2>/dev/null || git add -f .
git commit -q -m "chore: purge superseded vendor/toolchain/dist blobs from history; re-add current at HEAD"

# ---- Phase 2: verify locally ------------------------------------------------
log "Phase 2 — verify (size + checksum + HEAD assets)"
git reflog expire --expire=now --all; git gc --prune=now >/dev/null 2>&1
echo "  .git size after: $(git count-objects -vH | awk '/size-pack/{print $2,$3}')"
sha256sum -c vendor.tar.xz.sha256 >/dev/null && echo "  checksum invariant OK"
[[ -e vendor.tar.xz ]] || die "vendor.tar.xz missing at HEAD after rewrite!"
[[ $(ls toolchain/rust-toolchain-* 2>/dev/null | wc -l) -gt 0 ]] || die "toolchain archives missing at HEAD!"
echo "  commits preserved: $(git rev-list --count HEAD)   tags: $(git tag | wc -l)"
echo "  rewritten clone ready at: $TMP"

if [[ $PUSH -eq 0 ]]; then
  cat <<EOF

Local rewrite verified. Nothing on the remote or in your working repo changed.
Review $TMP, then re-run with --push to publish:
    bash scripts/internal/purge-git-history.sh --push
EOF
  exit 0
fi

# ---- Phase 3-5: guarded force-push ------------------------------------------
log "Phase 3 — disable storm workflows"
for wf in "${STORM_WORKFLOWS[@]}"; do gh workflow disable "$wf" --repo "$REPO_SLUG" 2>/dev/null && echo "  disabled $wf" || true; done

log "Phase 4 — force-push (temporarily allow force pushes on protected main)"
PROT="$(gh api "repos/$REPO_SLUG/branches/main/protection" 2>/dev/null || echo '')"
HAD_PROT=0; [[ -n "$PROT" ]] && HAD_PROT=1
if [[ $HAD_PROT -eq 1 ]]; then
  # reconstruct current protection with allow_force_pushes toggled; restore after
  echo "$PROT" | python -c '
import json,sys
p=json.load(sys.stdin)
def rpr(x):
  if not x: return None
  return {"dismiss_stale_reviews":x.get("dismiss_stale_reviews",False),"require_code_owner_reviews":x.get("require_code_owner_reviews",False),"required_approving_review_count":x.get("required_approving_review_count",0),"require_last_push_approval":x.get("require_last_push_approval",False)}
def rsc(x):
  if not x: return None
  return {"strict":x.get("strict",False),"contexts":x.get("contexts",[])}
out={"required_status_checks":rsc(p.get("required_status_checks")),"enforce_admins":p.get("enforce_admins",{}).get("enabled",False),"required_pull_request_reviews":rpr(p.get("required_pull_request_reviews")),"restrictions":None,"required_linear_history":p.get("required_linear_history",{}).get("enabled",False),"allow_force_pushes":True,"allow_deletions":p.get("allow_deletions",{}).get("enabled",False),"required_conversation_resolution":p.get("required_conversation_resolution",{}).get("enabled",False)}
json.dump(out,open("/tmp/bp-on.json","w"))
import copy; off=copy.deepcopy(out); off["allow_force_pushes"]=False; json.dump(off,open("/tmp/bp-off.json","w"))
'
  gh api -X PUT "repos/$REPO_SLUG/branches/main/protection" --input /tmp/bp-on.json >/dev/null && echo "  force-push temporarily enabled"
fi
git remote add origin "$ORIGIN_URL" 2>/dev/null || git remote set-url origin "$ORIGIN_URL"
git push --force origin main
git push --force --tags origin
if [[ $HAD_PROT -eq 1 ]]; then
  gh api -X PUT "repos/$REPO_SLUG/branches/main/protection" --input /tmp/bp-off.json >/dev/null && echo "  branch protection restored"
fi

log "Phase 5 — re-enable workflows"
for wf in "${STORM_WORKFLOWS[@]}"; do gh workflow enable "$wf" --repo "$REPO_SLUG" 2>/dev/null && echo "  enabled $wf" || true; done

# ---- Phase 6: sync the working repo -----------------------------------------
log "Phase 6 — sync working repo + reclaim local space"
cd "$REPO_ROOT"
git fetch origin --prune --prune-tags --force --tags --quiet
git reset --hard origin/main
git stash clear 2>/dev/null || true
git branch --list 'backup/stash-*' | tr -d ' ' | xargs -r git branch -D >/dev/null 2>&1 || true
git reflog expire --expire=now --all; git gc --prune=now >/dev/null 2>&1
echo "  working .git size now: $(git count-objects -vH | awk '/size-pack/{print $2,$3}')"

cat <<EOF

DONE. Remote history rewritten and working repo synced.
Follow-ups to check manually:
  * A force-push may spuriously trigger bundle-toolchain (auto-PR) + Docs — close/re-run as needed.
  * Backups kept at: $BK  (delete once confident, e.g. >= 2 weeks).
EOF
