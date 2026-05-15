# ci/jenkins/plugins/

This directory holds individual `.hpi` plugin files for Jenkins.  When populated
(by running `download.sh` below, or by committing the files directly), it gives IT
administrators a concrete set of files they can inspect, transfer, and install without
any internet access, Docker daemon, or special tooling.

The `.hpi` files are **not** committed to the repository by default — they are large
binary blobs that change independently of the source code.  Only commit them if your
workflow requires fully offline distribution of a known-good plugin set (similar to
how `vendor.tar.xz` ships Rust crate sources).  The `download.sh` script in this
directory is always committed and is enough to regenerate the files on demand.

---

## Choosing an installation path

Three paths are supported, listed from most to least automated.

---

### Path A — Admin with Docker (full transitive dependency tree)

**Recommended for fully air-gapped installs.**

Run `bundle-jenkins-plugins.sh` on any machine that has Docker and internet access.
It uses the official `jenkins-plugin-cli` to resolve and download the **complete
transitive dependency tree** — not just the direct plugins listed in `plugins.txt`.
The output is `jenkins-plugins.tar.xz` + `jenkins-plugins.tar.xz.sha256`.

```bash
# On a machine with Docker + internet:
bash ci/jenkins/bundle-jenkins-plugins.sh

# Commit both output files:
git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
git commit -m "ci: bundle Jenkins plugins for air-gapped install"
```

After that one-time step, every `git clone` has everything needed:

```bash
# On the air-gapped host:
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

See `ci/jenkins/README.md → "Installing plugins (air-gapped — recommended)"` for the
full Dockerfile and native-install variations.

---

### Path B — Admin without Docker

Use `download.sh` in this directory to populate `.hpi` files for the direct plugins
listed in `ci/jenkins/plugins.txt`.  No Docker required.

**Step 1 — Populate this directory:**

```bash
bash ci/jenkins/plugins/download.sh
```

Optional: re-download even when files already exist:

```bash
bash ci/jenkins/plugins/download.sh --force
```

Optional: point at an internal mirror instead of the Jenkins Update Center:

```bash
bash ci/jenkins/plugins/download.sh --update-center https://mirrors.example.com/jenkins
```

**Step 2 — Install into a running Jenkins instance:**

Copy the `.hpi` files to `$JENKINS_HOME/plugins/` and restart:

```bash
bash ci/jenkins/install-jenkins-plugins.sh --from-dir ci/jenkins/plugins --restart
```

Or copy manually:

```bash
cp ci/jenkins/plugins/*.hpi /var/jenkins_home/plugins/
# Docker:
docker restart <container-name>
# Native:
sudo systemctl restart jenkins
```

Or upload via the Jenkins UI one file at a time:
**Manage Jenkins → Plugins → Advanced → Deploy Plugin → Upload .hpi**

> **Transitive dependency note:** `download.sh` fetches only the direct plugins named
> in `plugins.txt`.  Jenkins resolves their transitive dependencies from the Update
> Center when it starts.  If the Jenkins host has no internet access and no Update
> Center, you need the full bundle from Path A instead.

**Optional — commit the files for distribution:**

```bash
git add ci/jenkins/plugins/*.hpi
git commit -m "ci: add pre-downloaded plugin files for offline install"
```

---

### Path C — No admin access (corporate Jenkins)

If you do not have shell access to the Jenkins host, three sub-options exist.

#### C1 — Request IT installation

Provide your IT/ops team with:

1. `ci/jenkins/plugins.txt` — the canonical plugin list with one-line descriptions
2. (Optional) the `.hpi` files in this directory — so they do not need to download anything

The table below lists every required plugin and what pipeline feature it enables:

| Plugin ID | What it enables |
|-----------|----------------|
| `workflow-aggregator` | Declarative Pipeline syntax — `stages {}`, `when {}`, `post {}` |
| `pipeline-utility-steps` | `readJSON` / `writeJSON` helpers used in the post-success block |
| `ws-cleanup` | `cleanWs()` in `post { cleanup }` — removes workspace after each build |
| `git` | `GitSCM` checkout step — clones the repository on the agent |
| `credentials-binding` | `credentials()` binding in `environment {}` blocks (SMTP, webhook) |
| `htmlpublisher` | `publishHTML()` — "SLOC Report" and "Build Dashboard" sidebar links |
| `plot` | `plot()` — SLOC trend charts across builds (code/comment/blank over time) |
| `junit` | `junit()` — "Test Result" sidebar link and pass/fail trend |
| `coverage` | `recordCoverage()` — line/branch/function % per build with drill-down |
| `pipeline-stage-view` | Stage visualization in the job UI (Blue Ocean lite) |
| `timestamper` | Timestamps on every console output line |
| `ansicolor` | ANSI colour in Rust compiler and Clippy output |
| `job-dsl` | Executes `ci/jenkins/seed-job.groovy` to create the pipeline job |
| `copyartifact` | Copies artifacts to/from downstream jobs in Pipeline-of-Pipelines setups |
| `bitbucket` | Bitbucket Branch Source — optional, Bitbucket SCM only |
| `bitbucket-build-status-notifier` | Posts commit statuses to Bitbucket — optional |

#### C2 — Upload via Jenkins UI

Requires the **"Administer"** permission in Jenkins (not just build permission).

**Manage Jenkins → Plugins → Advanced → Deploy Plugin → Upload .hpi**

Upload one `.hpi` file at a time.  You must also upload every transitive dependency
that is not already installed.  The output of `bundle-jenkins-plugins.sh` shows the
full dependency tree — use that as your list if you need a complete offline install.

This method works even when you cannot run CLI commands or SSH into the host.

#### C3 — Zero-plugin fallback (standalone HTML dashboard)

`ci/jenkins/generate-dashboard.py` generates a complete, self-contained HTML
dashboard from the CI output artifacts.  It requires only:

- Python 3 (standard library — no `pip install`)
- `archiveArtifacts` (Jenkins core — no extra plugins)

No `Plot`, `junit`, `coverage`, or `htmlpublisher` plugins are needed.  The generated
HTML file is archived as a build artifact and can be downloaded and opened in any
browser.

```bash
python3 ci/jenkins/generate-dashboard.py ci-out/
# Writes: ci-out/dashboard_<project>.html
# Archive it: archiveArtifacts artifacts: 'ci-out/dashboard_*.html'
```

The dashboard renders four sections:
- **SLOC Summary** — code / comment / blank line counts and files analyzed
- **Language Breakdown** — horizontal bar chart of code lines per language
- **Test Results** — pass / fail / skip / error counts (appears when `junit.xml` exists)
- **Code Coverage** — line coverage percentage progress bar (appears when `lcov.info` exists)

The Jenkinsfile already calls this script in the Archive & Publish stage and archives
the result.  No extra pipeline configuration is required.

See `ci/jenkins/README.md → "No admin access / corporate Jenkins"` for a comparison
of what each plugin adds versus what the fallback provides.

---

## What is stored here

| File | Description |
|------|-------------|
| `README.md` | This file |
| `download.sh` | Downloads `.hpi` files for all plugins in `plugins.txt` |
| `*.hpi` | Pre-downloaded plugin files (present only if you ran `download.sh` and committed) |
