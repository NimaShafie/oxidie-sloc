# Atlassian Suite Integration — Production Test Plan

**Scope:** validate that oxide-sloc can publish finished reports to **Confluence**
(Cloud + Server/DC) and post commit build-status to **Bitbucket** (Cloud +
Server/DC), across three privilege tiers:

1. **System / site admin** — easiest; can install anything and provision everything.
2. **Project / space admin** — can manage one project/space but cannot install apps.
3. **No admin** — hardest; a plain user with only content/repo permissions.

This document is written to be handed to the infrastructure agent that spins up
the Atlassian + Jenkins instances. Every step lists the exact permission, token
scope, and expected result so a pass/fail can be recorded without guesswork.

---

## 0. Architecture — why this is testable without admin

oxide-sloc integrates over **two independent surfaces**, both of which speak
**plain REST with a bearer/basic token**. Neither requires an Atlassian
Marketplace app (Connect/Forge) or a mandatory Jenkins plugin.

| Surface | Confluence | Bitbucket | Code |
|---|---|---|---|
| **Application** (`sloc-web`) | Native REST client: create/update page, versioning, upload HTML+PDF as attachments, SSRF guard | (report is hosted by the app; status posting is CI-side) | `crates/sloc-web/src/confluence.rs`, `integrations.rs` |
| **Jenkins CI** | `notify-confluence.py` — upsert summary page + attach HTML/PDF | `notify-bitbucket.sh` — POST commit build-status | `ci/jenkins/`, wired at `Jenkinsfile` `post{always}` → `runBitbucketNotify()` |

**Consequence for the privilege tiers:** the *functionality* (page create/update,
attachment upload, build-status POST) needs only **content-level** permissions and
a token. Admin rights are needed **only** to:

- install the two **optional** Jenkins plugins (`bitbucket`,
  `bitbucket-build-status-notifier`), and
- **provision** spaces/repos/permissions and mint tokens.

That is exactly why Tier 3 (no admin) is achievable — but "hardest", because it
depends entirely on the plugin-independent REST path and on someone else having
pre-provisioned the space/repo/permissions.

### Design notes the tester must know

- **Idempotency:** re-publishing the same page **title** updates the existing page
  (new version) instead of duplicating. Re-posting the same attachment **filename**
  updates that attachment to a new version.
- **Fail-safe / air-gap:** every integration point is opt-in and **exits 0** when
  its URL or credential is missing or the endpoint is unreachable. A missing/broken
  Atlassian target must **never** fail the Jenkins build.
- **SSRF guard (app only):** the web app blocks loopback, link-local, and
  cloud-metadata hosts, but **allows RFC-1918 private ranges** so self-hosted
  Server/DC on a corporate LAN stays reachable. The CI scripts do not enforce this
  (they run in a trusted CI context).
- **Report format:** the Confluence page carries a metrics **summary table + a link
  back** to the app/Jenkins-hosted report, **and** the full **HTML + PDF** report
  is uploaded as page **attachments** (so it is viewable inside Confluence with no
  link-out).

---

## 1. Plugins / third-party extensions to bundle in this package

### Atlassian side — none required
No Confluence or Bitbucket Marketplace app is required. All calls use the
first-party REST APIs (Confluence Cloud v2 / Server v1; Bitbucket Cloud 2.0 /
Server `build-status/1.0`). **Do not** install any add-on for the core test.

### Jenkins side — two optional plugins (NOT pre-bundled in the repo)
Both are listed in `ci/jenkins/plugins.txt`:

| Plugin | Purpose | Required? |
|---|---|---|
| `bitbucket` | Bitbucket Branch Source (SCM) | Optional |
| `bitbucket-build-status-notifier` | `bitbucketStatusNotify()` build-status step | Optional |

> **Important:** the offline bundle `jenkins-plugins.tar.xz` (+ `.sha256`) is **not
> committed to the repo** — it is a multi-tens-of-MB binary that must be generated
> on demand. `ci/jenkins/Dockerfile.controller` COPYs it, so the controller image
> also expects it to be produced first. Do not assume a fresh checkout already
> contains it; the `install-jenkins-plugins.sh` header reflects this.

- **Producing the bundle (once, on a networked machine):**
  `bash ci/jenkins/bundle-jenkins-plugins.sh` (needs Docker + internet) writes
  `jenkins-plugins.tar.xz{,.sha256}` to the repo root. Commit them only if you want
  a truly offline clone; otherwise they stay local.
- **Installing them offline (Tier 1/2 with a Jenkins admin), after producing the
  bundle:** `bash ci/jenkins/install-jenkins-plugins.sh` (verifies the `.sha256`,
  unpacks the bundle into `$JENKINS_HOME/plugins`, restarts).
- **No-Docker fallback:** `bash ci/jenkins/plugins/download.sh` populates
  `ci/jenkins/plugins/*.hpi` (direct plugins only), then
  `bash ci/jenkins/install-jenkins-plugins.sh --from-dir ci/jenkins/plugins`. The
  install script auto-detects this directory when the tar.xz bundle is absent.
- **When absent** (Tier 3, or an admin who declined to install): the plugin call in
  `runBitbucketNotify()` is wrapped in try/catch (`catch (Throwable)`, so an absent
  step throwing `NoSuchMethodError` is caught) and the **plugin-independent**
  `notify-bitbucket.sh` REST path takes over. Build-status still posts.

### Agent prerequisites (all tiers)
- `python3` (stdlib only — no pip) for `notify-confluence.py`
- `curl` for `notify-bitbucket.sh`
- `bash`

---

## 2. Jenkinsfile wiring (verify before any run)

The integration is wired into the pipeline `post { always }` block:

```
post { always { script { if (h != null) { h.runBitbucketNotify() } } } }
```

`runBitbucketNotify()` (`ci/jenkins/pipeline-helpers.groovy`) does, in order:
1. `bitbucketStatusNotify(...)` via the plugin **if installed** (try/catch).
2. `notify-bitbucket.sh <state>` — plugin-independent commit build-status POST.
3. `notify-confluence.py <outDir> <proj>` — upsert page + attach HTML/PDF.

**Configuration inputs** are now first-class Jenkins **job parameters** (added to
`Jenkinsfile` `parameters{}`, bringing the form to **58** parameters). Declarative
parameters are auto-exposed as environment variables, so the helper reads them
directly:

| Parameter | Applies to | Example |
|---|---|---|
| `CONFLUENCE_BASE_URL` | both tiers | `https://confluence.corp.com` or `https://acme.atlassian.net/wiki` |
| `CONFLUENCE_USER` | Cloud basic auth (blank ⇒ Server PAT/Bearer) | `ci-bot@acme.com` |
| `CONFLUENCE_SPACE_KEY` | required to publish | `DEV` |
| `CONFLUENCE_PARENT_ID` | optional nesting | `65601` |
| `CONFLUENCE_PAGE_TITLE` | optional (blank ⇒ `oxide-sloc — <JOB_NAME>`) | `oxide-sloc — payments-api` |
| `BITBUCKET_BASE_URL` | both tiers | `https://bitbucket.corp.com` or `https://api.bitbucket.org` |
| `BITBUCKET_WORKSPACE` | Cloud only | `acme` |
| `BITBUCKET_REPO` | Cloud only | `payments-api` |

**Tokens are NOT parameters** — add them as Jenkins **Secret Text** credentials so
they are masked in the log:

| Credential ID | Value |
|---|---|
| `confluence-api-token` | Confluence PAT (Server/DC) **or** Cloud API token |
| `bitbucket-build-token` | Bitbucket HTTP access token / app password |

If a credential is absent, that half of `runBitbucketNotify()` logs a one-line
"skipped" note and continues (build stays green).

---

## 3. Provisioning matrix (what the infra agent must create per tier)

For each tier, stand up: a Confluence instance, a Bitbucket instance (Cloud and/or
Server/DC as you wish to cover), and a Jenkins with the oxide-sloc pipeline job.
Provisioning is done by an admin **once**; the *test user's* effective permission
is what defines the tier.

| Resource | Tier 1 (system admin) | Tier 2 (project/space admin) | Tier 3 (no admin) |
|---|---|---|---|
| Confluence space | test user creates it | space pre-created; test user is **space admin** | space pre-created by someone else; test user granted only **Add Page** |
| Confluence token | own PAT / API token | own PAT / API token | own PAT / API token |
| Bitbucket repo | test user creates it | project pre-created; test user is **project admin** | repo pre-created; test user granted **Repo Write** only |
| Bitbucket token scope | full | `repository:write` (+ admin of the project) | `repository:write` only |
| Jenkins plugins | test user installs both | already installed by admin (or absent) | **absent** — REST path only |
| Jenkins job config | test user edits freely | test user has Job/Configure | test user has Job/Build only |

### Minimum permissions for the REST calls to succeed (the crux)

- **Confluence create/update page:** space permission **"Add Page"** (`Pages: Add`).
  No space-admin, no site-admin required.
- **Confluence attachment upload:** same page/space **Add** permission (attachments
  inherit page permissions).
- **Bitbucket Server/DC build-status POST** (`/rest/build-status/1.0/commits/{sha}`):
  token owner needs **REPO_READ** on a repo containing the commit.
- **Bitbucket Cloud build-status POST**
  (`/2.0/repositories/{ws}/{repo}/commit/{sha}/statuses/build`): app password /
  token with **`repository:write`**.

If Tier 3 fails only because a permission above is missing, that is a
**provisioning** failure, not a product failure — record it as such.

---

## 4. Test cases (run for each tier; note tier-specific expectations)

Legend: **App** = via web UI/REST on `sloc-web`; **CI** = via a Jenkins build.

### Group A — Confluence publish (App)

| ID | Steps | Expected |
|---|---|---|
| A1 | `/integrations` → Confluence tab → enter base URL, user (Cloud) or blank (Server PAT), space key, token → **Test connection** | `200`/OK. Wrong token ⇒ friendly "Connection test failed" (BAD_GATEWAY), no stack trace. |
| A2 | Run a scan, then **Post to Confluence** with a new title | New page created in the space; returns `page_id`. |
| A3 | Post again with the **same title** | Existing page **updated** (version N→N+1); **no duplicate** page. |
| A4 | Inspect the page | Metrics summary table + working **report link**; **`oxide-sloc-report.html`** and **`oxide-sloc-report.pdf`** appear under **Attachments**. |
| A5 | Set base URL to `http://169.254.169.254` / `http://localhost` and save/test | **422**, SSRF blocked. |
| A6 | Set base URL to a private `https://10.x` self-hosted Server | Allowed (not blocked) — reaches the server. |

### Group B — Confluence publish (CI)

| ID | Steps | Expected |
|---|---|---|
| B1 | Build with `CONFLUENCE_*` params + `confluence-api-token` set | Log: `notify-confluence: created page '…'` then `attachment 'oxide-sloc-report.html' uploaded` (and `.pdf`). |
| B2 | Re-build (same title) | Log: `updated page '…' (vN)`; attachments updated, not duplicated. |
| B3 | Build with `CONFLUENCE_BASE_URL` **blank** | Log: `not configured … skipping.` Build **green**. |
| B4 | Build with an **unreachable** base URL (air-gap sim) | Log: `Confluence unreachable … skipping cleanly.` Build **green**. |
| B5 | Build with a **bad token** | Log: `create/update failed (401/403) …` Build **green** (non-fatal). |

### Group C — Bitbucket build-status (CI)

| ID | Steps | Expected |
|---|---|---|
| C1 | Build a commit with `BITBUCKET_*` params + `bitbucket-build-token` | `notify-bitbucket: posted SUCCESSFUL for <sha> → Bitbucket (2xx)`. Status visible on the commit. (Server/DC returns **204 No Content**; Cloud returns **201** — assert any `2xx`, not a literal `200/201`. `notify-bitbucket.sh` prints the actual code.) |
| C2 | Force a failing build | Status **FAILED** posted for the same commit. |
| C3 | Cloud target with `BITBUCKET_WORKSPACE`/`BITBUCKET_REPO` blank | `Cloud needs BITBUCKET_WORKSPACE + BITBUCKET_REPO — skipping.` Build green. |
| C4 | No `bitbucket-build-token` credential | `Bitbucket direct notify skipped … ` Build green. |
| C5 | (Tier 1/2 only) plugin installed | `bitbucketStatusNotify` also fires; no double-failure if both run. |

### Group D — Tier-specific expectations

| ID | Tier | Expectation |
|---|---|---|
| D1 | **1 – system admin** | All of A–C pass; plugin path (C5) exercised; can also install a Marketplace app if desired (not required). |
| D2 | **2 – project/space admin** | A–C pass **without** installing any app; page/attachment/status all succeed with space-admin + project-admin + `repository:write`. Cannot install apps — confirm the REST path is what's exercised. |
| D3 | **3 – no admin** | A–C pass using only **Add Page** (Confluence) + **Repo Write** (Bitbucket) + a personal token; **no** Jenkins plugin present (plugin path logs "skipped", REST path succeeds). Any failure must trace to a missing content/repo permission (provisioning), not to code. |

---

## 5. Pass / fail criteria (production readiness)

The integration is production-ready when **all** hold for every tier under test:

- [ ] Confluence page **created** on first publish and **updated** (versioned) on
      repeat — never duplicated (A2/A3, B1/B2).
- [ ] Full **HTML + PDF** report present as page **attachments** (A4, B1).
- [ ] Working **report link** and correct **summary table** on the page.
- [ ] Bitbucket commit shows **SUCCESSFUL**/**FAILED** matching the build (C1/C2).
- [ ] Every **unconfigured / unreachable / unauthorized** path is **non-fatal**
      (build stays green): B3/B4/B5, C3/C4.
- [ ] **SSRF** loopback/metadata blocked; RFC-1918 allowed (A5/A6).
- [ ] Tier 3 succeeds with **no admin** and **no Jenkins plugin** (D3).
- [ ] No token or secret is printed in any Jenkins log line.

---

## 6. Quick reference — env/credential cheat-sheet

**App (`sloc-web`)** — configure at `/integrations` or via env:
```
SLOC_CONFLUENCE_TOKEN=<token>     # overrides the stored credential at load time
```

**CI (Jenkins job params + Secret Text credentials):**
```
# Confluence
CONFLUENCE_BASE_URL, CONFLUENCE_USER, CONFLUENCE_SPACE_KEY,
CONFLUENCE_PARENT_ID, CONFLUENCE_PAGE_TITLE      # job parameters
confluence-api-token                              # Secret Text credential

# Bitbucket
BITBUCKET_BASE_URL, BITBUCKET_WORKSPACE, BITBUCKET_REPO   # job parameters
bitbucket-build-token                                     # Secret Text credential
```

**Manual REST smoke tests (outside Jenkins), for the infra agent:**
- Confluence Server page list (auth check):
  `curl -H "Authorization: Bearer $TOKEN" "$BASE/rest/api/space?limit=1"`
- Confluence Cloud space list:
  `curl -u "$USER:$TOKEN" "$BASE/wiki/api/v2/spaces?limit=1"`
- Bitbucket Server build-status read:
  `curl -H "Authorization: Bearer $TOKEN" "$BASE/rest/build-status/1.0/commits/$SHA"`

See also `testing/examples/confluence/update-sloc-page.sh` and
`testing/examples/bitbucket/bitbucket-pipelines.yml` for standalone examples, and
`docs/ci-integrations.md` for the full CI integration reference.
