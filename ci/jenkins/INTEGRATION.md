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
| `TARGET_REF` | branch / tag / SHA (blank = the repo's default branch) |
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

---

## Notes

- `REPO_URL` (far down, optional) is the **tooling** repo the scanner is built
  from — normally the public oxide-sloc repo or your fork. It is *not* the repo
  you scan; that's `TARGET_REPO_URL`.
- `SCAN_PATH` is resolved **inside the target repo** when `TARGET_REPO_URL` is
  set. Blank scans the whole repo; a bad subtree fails fast with a clear message.
- Serve Jenkins over HTTPS (`ci/jenkins/https/`) before sending tokens over the
  API — plain HTTP exposes them in transit.
