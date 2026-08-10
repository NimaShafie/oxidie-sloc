# Integrating oxide-sloc with your existing repos

The `oxide-sloc` Jenkins job is designed to analyze **any existing repository**
on GitHub, GitLab, or Bitbucket (or a local/air-gapped mirror). There are two
ways to wire it up — use whichever fits, or both.

```
  Way 1 (pull)   Jenkins  ── clones ──▶  your repo        "point Jenkins at the repo"
  Way 2 (push)   your CI  ── triggers ─▶ Jenkins job      "point the repo at Jenkins"
```

Under the hood it's a plain `git clone`, so it is SCM-agnostic — GitHub, GitLab,
Bitbucket Cloud/Server, and `file://` all work the same way.

---

## Way 1 — point Jenkins at your repo (pull)

**Build with Parameters** and set just the top of the form:

| Parameter | Value |
|---|---|
| `TARGET_REPO_URL` | your repo's Git URL, e.g. `https://gitlab.com/acme/widgets.git` |
| `TARGET_REF` | branch / tag / SHA (blank defaults to `main` — set e.g. `master` for repos whose default branch is not `main`) |
| `TARGET_CREDENTIALS_ID` | a Jenkins credential ID — **only for private repos** |
| `SCAN_PATH` | **blank = scan the whole repo** (or `src`, `packages/api`, …) |

Everything below the `CHANGE_DEFAULT_SCAN_SETTINGS` divider is optional and
pre-set to sensible defaults. **Point at the repo, hit Build — that's it.**

### Private repos — one-time credential setup

1. **Manage Jenkins → Credentials → (a store) → Add Credentials.**
2. For an **HTTPS** URL: *Username with password* — username = your git user (or
   `x-token-auth` on Bitbucket / `oauth2` on GitLab / any name on GitHub), password
   = a **personal access token** with read/clone scope.
   For an **SSH** URL (`git@…` / `ssh://`): *SSH Username with private key*.
3. Give it a memorable **ID** (e.g. `acme-scm`) and paste that ID into
   `TARGET_CREDENTIALS_ID`.

Leave `TARGET_CREDENTIALS_ID` blank for public repos, or when the Jenkins agent
already has git access (SSH agent / credential helper / local mirror).

---

## Way 2 — trigger Jenkins from your repo's CI (push)

Add a step to your existing pipeline that calls the Jenkins REST API
`buildWithParameters`, passing your repo + commit. Authenticate with a **Jenkins
API token** (Manage Jenkins → Users → your user → *Configure* → *API Token*);
API-token requests are exempt from the CSRF crumb, so no crumb fetch is needed.

Store `JENKINS_URL`, `JENKINS_USER`, `JENKINS_TOKEN` as secrets in your CI.

### GitHub Actions

```yaml
- name: Trigger oxide-sloc scan
  run: |
    curl -fsS -X POST \
      --user "${{ secrets.JENKINS_USER }}:${{ secrets.JENKINS_TOKEN }}" \
      "${{ secrets.JENKINS_URL }}/job/oxide-sloc/buildWithParameters" \
      --data-urlencode "TARGET_REPO_URL=${{ github.server_url }}/${{ github.repository }}.git" \
      --data-urlencode "TARGET_REF=${{ github.sha }}" \
      --data-urlencode "TARGET_CREDENTIALS_ID=github-scm"   # omit for public repos
```

### GitLab CI

```yaml
oxide-sloc-scan:
  script:
    - >
      curl -fsS -X POST
      --user "$JENKINS_USER:$JENKINS_TOKEN"
      "$JENKINS_URL/job/oxide-sloc/buildWithParameters"
      --data-urlencode "TARGET_REPO_URL=$CI_REPOSITORY_URL"
      --data-urlencode "TARGET_REF=$CI_COMMIT_SHA"
      --data-urlencode "TARGET_CREDENTIALS_ID=gitlab-scm"
```

### Bitbucket Pipelines

```yaml
- step:
    name: oxide-sloc scan
    script:
      - >
        curl -fsS -X POST
        --user "$JENKINS_USER:$JENKINS_TOKEN"
        "$JENKINS_URL/job/oxide-sloc/buildWithParameters"
        --data-urlencode "TARGET_REPO_URL=$BITBUCKET_GIT_HTTP_ORIGIN.git"
        --data-urlencode "TARGET_REF=$BITBUCKET_COMMIT"
        --data-urlencode "TARGET_CREDENTIALS_ID=bitbucket-scm"
```

### Auto-scan on every push (webhook, optional)

Install the **Generic Webhook Trigger** plugin, add a webhook on your repo
pointing at `${JENKINS_URL}/generic-webhook-trigger/invoke?token=...`, and map the
payload's clone-URL + commit fields to `TARGET_REPO_URL` / `TARGET_REF`. Then a
scan runs automatically on every push with no code in your repo at all.

---

## Chaining external scans (Pipeline-of-Pipelines)

`oxide-sloc` can trigger a downstream job on success (`DOWNSTREAM_JOB`) and be
triggered by an upstream orchestrator — see `ci/jenkins/demo/`. Chaining does not
auto-forward the target params, so an orchestrator that wants a specific repo
scanned passes them explicitly:

```groovy
build job: 'oxide-sloc', wait: true, parameters: [
  string(name: 'TARGET_REPO_URL',       value: 'https://github.com/acme/widgets.git'),
  string(name: 'TARGET_REF',            value: 'main'),
  string(name: 'TARGET_CREDENTIALS_ID', value: 'github-scm'),   // private repos
  string(name: 'DOWNSTREAM_JOB',        value: 'oxide-sloc-chain-downstream'),
]
```

A **multi-repo fan-out** is just this call in a loop over a list of repo URLs —
one oxide-sloc job scans your whole fleet, each run optionally chaining a
consumer.

### Chaining + Atlassian notify behavior

The Atlassian notify step runs in the pipeline's `post { always }` block, so it
fires **once per `oxide-sloc` build regardless of chaining** — every upstream- or
orchestrator-triggered run posts its own Confluence page + Bitbucket status. Key
points for chained topologies:

- `runBitbucketNotify()` uses **that build's own** `GIT_COMMIT` and
  `SLOC_PROJECT`, so a fan-out over N repos produces N independent Confluence
  pages / N commit statuses — no cross-talk.
- The `DOWNSTREAM_JOB` is triggered from `post { success }` **before** cleanup;
  the notify in `post { always }` is independent of whether a downstream job is
  configured, and a downstream failure does not suppress the notify.
- Re-using the same `CONFLUENCE_PAGE_TITLE` across chained builds updates one page
  (versioned); give each repo a distinct title (or leave it blank to default to
  `oxide-sloc — <JOB_NAME>`) to keep them separate.

---

## Job topology (seed → main → manual)

All oxide-sloc Jenkins jobs are **one pipeline definition** — the committed
`Jenkinsfile` — seeded under one or more job names. They therefore share the
identical stage logic, `ci/jenkins/pipeline-helpers.groovy` helpers, and the
`post { always } { runBitbucketNotify() }` wiring **by construction**; there is no
second pipeline that could drift.

```
  oxide-sloc-seed  (Job DSL, ci/jenkins/seed-job.groovy)
        │  pipelineJob(JOB_NAME) { … cpsScm { scriptPath('Jenkinsfile') } }
        ▼
  oxide-sloc       (main SCM pipeline — JOB_NAME default)
  oxide-sloc-manual(same Jenkinsfile, seeded with JOB_NAME=oxide-sloc-manual
                    when 'oxide-sloc' already exists on the controller)
```

- **`oxide-sloc-seed`** — a Freestyle job (or Script Console one-shot) that runs
  `seed-job.groovy` to create/update the pipeline job. Override `JOB_NAME` /
  `REPO_URL` via seed-job parameters or env vars.
- **`oxide-sloc`** — the canonical pipeline. First build is unparameterized
  (Jenkins discovers `parameters{}` only after one run); from build #2 the full
  "Build with Parameters" form (incl. all `CONFLUENCE_*` / `BITBUCKET_*` fields)
  appears.
- **`oxide-sloc-manual`** — not a separate file: it is the same `Jenkinsfile`
  seeded under a different name (the seed script documents this). Because both
  load `Jenkinsfile` → `pipeline-helpers.groovy`, the Atlassian params, credential
  IDs, and notify wiring are guaranteed identical. To create it, run the seed with
  `JOB_NAME=oxide-sloc-manual`.

`ci/jenkins/job-config.xml` (and its `.tmpl`) is an alternative way to import the
same pipeline as XML — it also points `scriptPath` at `Jenkinsfile`, so it inherits
the identical wiring.

---

## Atlassian plugin-optional design

After every build, `post { always }` → `runBitbucketNotify()` publishes a
Confluence summary page (+ HTML/PDF attachments) and posts a Bitbucket commit
build-status. Both are **opt-in and non-fatal** (they exit 0 when unconfigured or
unreachable) and **plugin-independent** (plain REST via
`ci/jenkins/notify-confluence.py` and `ci/jenkins/notify-bitbucket.sh`).

**The two Bitbucket Jenkins plugins are OPTIONAL.** `runBitbucketNotify()` will
call `bitbucketStatusNotify(...)` *if the plugin is installed*, but that call is
wrapped in **`catch (Throwable)`** — not `catch (Exception)`. This matters: when
the plugin is absent, Jenkins throws `java.lang.NoSuchMethodError`, which is a
`java.lang.Error`, **not** an `Exception`. An `Exception`-typed catch would let it
escape, abort `post { always }`, and skip the REST fallback — turning a
**no-admin / no-plugin (Tier 3)** build RED. The `Throwable` catch is what
guarantees the Tier-3 fallback and keeps the build green. (This is the "P0" fix; a
guard test at `ci/jenkins/tests/test-pipeline-helpers-guards.py` prevents
regression.)

See [`docs/ci-integrations.md` § Atlassian Suite](../../docs/ci-integrations.md#atlassian-suite-confluence--bitbucket--built-in-ci-integration)
for the 3-tier permission model, job parameters, credential IDs, Cloud-vs-Server
differences, the auth-scheme matrix, and a troubleshooting table.

### Offline Jenkins plugins

The optional plugins are listed in `ci/jenkins/plugins.txt`. **The offline bundle
`jenkins-plugins.tar.xz` (+ `.sha256`) is NOT committed to the repo** — it is a
multi-tens-of-MB binary that must be produced on demand. All three consumers agree
on this:

- `ci/jenkins/Dockerfile.controller` **COPYs** the bundle, so the controller image
  build also expects it to be generated first.
- `ci/jenkins/install-jenkins-plugins.sh` errors with a clear "run
  bundle-jenkins-plugins.sh first" message (and auto-falls back to
  `ci/jenkins/plugins/*.hpi` when present).
- `testing/atlassian-integration-test-plan.md` §1 documents the same.

To make the documented offline path work with no internet:

```bash
# once, on a networked machine with Docker:
bash ci/jenkins/bundle-jenkins-plugins.sh
git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256   # optional: commit for a truly offline clone
# then, on the (possibly air-gapped) controller:
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

No-Docker fallback (direct plugins only, transitive deps resolved at startup):

```bash
bash ci/jenkins/plugins/download.sh
bash ci/jenkins/install-jenkins-plugins.sh --from-dir ci/jenkins/plugins
```

Because the plugins are **optional**, none of this is required for a working
build: with no plugins installed, the plugin-independent REST path posts the
Bitbucket status and Confluence page anyway (Tier-3).

---

## Notes

- `REPO_URL` (far down, optional) is the **tooling** repo the scanner is built
  from — your instance, fork, or mirror. It is *not* the repo you scan; that's
  `TARGET_REPO_URL`. **No internet URL is hardcoded anywhere.** It resolves in
  order: the `REPO_URL` build parameter → the `REPO_URL` environment variable
  (a Jenkins global property, typically sourced from `ci/jenkins/.env`) → the
  job's own configured SCM (`checkout scm`). Leave it **blank on an air-gapped
  controller** whose job already points at a local mirror and the build never
  reaches out to github.com. `REPO_BRANCH` (default `main`) overrides the ref
  when you set an explicit `REPO_URL`. Use a concrete ref, not the wildcard
  `*/main`: lightweight (jgit) SCM checkout NPEs on a wildcard at Jenkinsfile load.
- `SCAN_PATH` is resolved **inside the target repo** when `TARGET_REPO_URL` is
  set. Blank scans the whole repo; a bad subtree fails fast with a clear message.
- Serve Jenkins over HTTPS (`ci/jenkins/https/`) before sending tokens over the
  API — plain HTTP exposes them in transit.
