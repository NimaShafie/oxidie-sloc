# Jenkins Manual Setup Guide — oxide-sloc

This guide walks through creating the oxide-sloc pipeline job in Jenkins entirely through
the web UI, with no CLI or scripting required.  Follow every numbered step in order.
Each section maps to one Jenkins screen.

> **Tip:** If you prefer a scripted bootstrap, see `ci/jenkins/README.md` for the CLI
> approach using `job-config.xml` and `seed-job.groovy`.

---

## Table of contents

1. [Prerequisites](#1-prerequisites)
2. [Install Jenkins](#2-install-jenkins)
3. [Complete the setup wizard](#3-complete-the-setup-wizard)
4. [Install required plugins](#4-install-required-plugins)
5. [Add credentials](#5-add-credentials)
6. [Configure the CSP header (HTML report viewer)](#6-configure-the-csp-header-html-report-viewer)
7. [Create the pipeline job](#7-create-the-pipeline-job)
8. [Configure the pipeline job](#8-configure-the-pipeline-job)
9. [Seed the parameters form (first build)](#9-seed-the-parameters-form-first-build)
10. [Run a real build](#10-run-a-real-build)
11. [Verify all features](#11-verify-all-features)
12. [Agent setup — Rust toolchain](#12-agent-setup--rust-toolchain)
13. [Optional agent setup — cargo-nextest (JUnit test results)](#13-optional-agent-setup--cargo-nextest-junit-test-results)
14. [Optional agent setup — cargo-llvm-cov (coverage)](#14-optional-agent-setup--cargo-llvm-cov-coverage)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Prerequisites

| Requirement | Details |
|-------------|---------|
| Jenkins LTS | 2.387.x or later recommended |
| Agent OS | Linux (x86_64) — the Rust toolchain and shell scripts require bash |
| Disk space | ~2 GB free on the agent: 400 MB toolchain + vendor archive + build output |
| Git | Must be on the agent's `PATH` |
| Internet access | Required to install Jenkins (Options B/C/D) and download plugins (Step 4 Option B). Not needed after `git clone` if `jenkins-plugins.tar.xz` is committed to the repo (Options A and E). |

---

## 2. Install Jenkins

**Which option for your setup?**

| Scenario | Option |
|----------|--------|
| Fully online — no restrictions | B, C, or D |
| Online but no Docker | C or D |
| Air-gapped with Docker | A |
| Air-gapped without Docker | E |
| Air-gapped, no networked machine, no Docker | E (requires `jenkins-plugins.tar.xz` committed to repo) |

> **Options A & E pre-requisite:** `jenkins-plugins.tar.xz` must be committed to the
> repository root.  Run `bash ci/jenkins/bundle-jenkins-plugins.sh` once on a networked
> + Docker machine, then commit both output files:
> ```bash
> git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
> git commit -m "ci: bundle Jenkins plugins for air-gapped install"
> ```
> After that one-time step, a plain `git clone` is all any air-gapped host needs —
> no internet, no Docker, no separate download step.

### Option A — Bundled controller image (air-gapped, Docker)

This image is built from `ci/jenkins/Dockerfile.controller` and has every required
plugin installed from `jenkins-plugins.tar.xz` bundled into the archive.
Requires Docker.  Once `jenkins-plugins.tar.xz` is generated and committed (see below),
no internet access is needed after `git clone`.

**No internet access needed once `jenkins-plugins.tar.xz` is committed to the repo.**

```bash
# From the repository root — ensure jenkins-plugins.tar.xz is present:
ls jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256

# Build the controller image:
docker build \
    -t jenkins-oxide-sloc-controller:latest \
    -f ci/jenkins/Dockerfile.controller \
    .

# Run:
docker run -d \
    --name jenkins-controller \
    -p 8080:8080 \
    -v jenkins_home:/var/jenkins_home \
    jenkins-oxide-sloc-controller:latest
```

If `jenkins-plugins.tar.xz` is not yet present in the repo, generate it once on a
networked machine and commit it:

```bash
bash ci/jenkins/bundle-jenkins-plugins.sh   # requires Docker + internet
git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
git commit -m "ci: bundle Jenkins plugins for air-gapped install"
```

Open `http://localhost:8080` in a browser and proceed to Step 3.
The setup wizard is **disabled** in this image — go straight to
[Step 5 (Add credentials)](#5-add-credentials).

### Option B — Plain Docker (online, manual plugin install)

```bash
docker run -d \
  --name jenkins \
  -p 8080:8080 \
  -v jenkins_home:/var/jenkins_home \
  jenkins/jenkins:lts-jdk21
```

Open `http://localhost:8080`, complete the setup wizard, then follow Step 4 below
to install plugins manually.

### Option C — Native package (Debian/Ubuntu)

```bash
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key \
  | sudo tee /usr/share/keyrings/jenkins-keyring.asc > /dev/null
echo "deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/" \
  | sudo tee /etc/apt/sources.list.d/jenkins.list > /dev/null
sudo apt-get update && sudo apt-get install -y jenkins
```

After starting Jenkins, install bundled plugins without internet access:

```bash
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

### Option D — Native package (RHEL/CentOS/Rocky)

```bash
sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key
sudo yum install -y jenkins && sudo systemctl start jenkins
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

### Option E — Native package, air-gapped (no Docker)

For hosts with no internet access and no Docker.  Requires `jenkins-plugins.tar.xz`
committed to the repository root (see the pre-requisite note at the top of this section).

Install Jenkins via your local package mirror (substitute the mirror URL for the
public `pkg.jenkins.io` URL in Option C or D), then install plugins from the committed
archive:

```bash
# From the repository root on the Jenkins host:
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

`install-jenkins-plugins.sh` finds `jenkins-plugins.tar.xz` in the repository root,
verifies its SHA-256 checksum, extracts every plugin to `$JENKINS_HOME/plugins/`,
pins each plugin to prevent update-center replacement, and restarts Jenkins.

No internet access is needed after `git clone` provided the archive is committed.

Open `http://localhost:8080`, complete the setup wizard, then skip ahead to
[Step 5 (Add credentials)](#5-add-credentials) — plugins are already installed.

---

## 3. Complete the setup wizard

> **Skip this step** if you used Option A (bundled controller image) — the wizard
> is disabled in that image.  Proceed directly to [Step 5](#5-add-credentials).

1. **Get the unlock password:**
   - Docker: `docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword`
   - Native: `sudo cat /var/lib/jenkins/secrets/initialAdminPassword`

2. Paste the password at `http://<host>:8080/`.

3. On the "Customize Jenkins" screen, choose **"Install suggested plugins"**.
   Wait for the installation to finish (takes ~2 minutes).

4. Create the first admin user:
   - Fill in **Username**, **Password**, **Full name**, **Email address**.
   - Click **Save and Continue**.

5. Confirm the Jenkins URL shown (e.g., `http://10.0.0.8:8080/`) and click
   **Save and Finish → Start using Jenkins**.

---

## 4. Install required plugins

> **Skip this step** if you used Option A (bundled Docker image) or Option E
> (native air-gapped), or if you already ran `install-jenkins-plugins.sh` during
> Step 2 — all plugins are already installed and pinned.

The suggested-plugin set from Step 3 installs the basics.  Install the remaining
oxide-sloc-specific plugins via the Jenkins UI:

### Option A — From the bundled archive (air-gapped)

```bash
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

This extracts every plugin from `jenkins-plugins.tar.xz`, pins them so the update
center cannot replace them, and restarts Jenkins.

### Option B — Manual install via the Jenkins UI (internet required)

1. Go to **Manage Jenkins → Plugins → Available plugins**.

2. Search for and check each of the following:

   | Plugin (search term) | Purpose |
   |---------------------|---------|
   | `Pipeline: Stage View` | Stage visualization in the job UI |
   | `HTML Publisher` | "SLOC Report — &lt;slug&gt;" / "Build Dashboard — &lt;slug&gt;" / "Coverage Report" sidebar links |
   | `Plot` | Build-over-build SLOC trend charts |
   | `JUnit` | "Test Result" sidebar link (cargo-nextest builds) |
   | `Coverage` | Native LCOV/Cobertura integration — line/branch % on build pages |
   | `Timestamper` | Timestamps on every console output line |
   | `AnsiColor` | ANSI colours in Rust compiler / clippy output |
   | `Job DSL` | Runs `seed-job.groovy` to create the pipeline job |
   | `Copy Artifact` | Copies artifacts between chained pipeline jobs |
   | `Credentials Binding` | Binds secrets as environment variables |
   | `Workspace Cleanup` | `cleanWs()` in `post { cleanup }` |
   | `Pipeline Utility Steps` | `readJSON`, `readFile`, `fileExists` in post steps |

   > **Optional — Bitbucket:** `Bitbucket Branch Source` and
   > `Bitbucket Build Status Notifier`.

3. Click **Install**, then check **"Restart Jenkins when installation is complete"**.

4. Wait for Jenkins to restart and log back in.

---

## 5. Add credentials

The pipeline uses Jenkins credentials to keep secrets out of build logs and the
Jenkinsfile itself.  Add only the credentials that match the features you intend to use.

### 5a. Navigate to the credentials store

**Manage Jenkins → Credentials → System → Global credentials (unrestricted)**
→ **Add Credentials** (button in the left sidebar or top-right).

### 5b. SonarQube analysis token

> **Note:** The SonarQube pipeline stage was removed in the current Jenkinsfile.
> SonarQube analysis is now run externally via `ci/sonar/` scripts and the
> `SONAR_URL` / `SONAR_TOKEN` environment variables, not through a Jenkins
> credential binding.  The `sonarqube-oxide-sloc-token` credential ID described
> in older docs is **not consumed by the current Jenkinsfile** — you do not need
> to create it.  Skip this step unless you have re-added a SonarQube stage to a
> custom Jenkinsfile.

### 5c. Artifact repository (required for artifact push stage)

Add **two** credentials, one for the username and one for the password/token:

**Credential 1:**
| Field | Value |
|-------|-------|
| Kind | **Secret text** |
| Secret | Your artifact repo username or access-key ID |
| ID | `SLOC_ARTIFACT_REPO_USER` |

**Credential 2:**
| Field | Value |
|-------|-------|
| Kind | **Secret text** |
| Secret | Your artifact repo password, API token, or secret key |
| ID | `SLOC_ARTIFACT_REPO_PASS` |

### 5d. Webhook Bearer token (optional)

| Field | Value |
|-------|-------|
| Kind | **Secret text** |
| Secret | Your webhook Bearer token |
| ID | `SLOC_WEBHOOK_TOKEN` |

### 5e. Email / SMTP (optional)

Add **three** credentials:

| ID | Secret value |
|----|-------------|
| `SLOC_SMTP_HOST` | SMTP server hostname (e.g., `smtp.example.com`) |
| `SLOC_SMTP_USER` | SMTP username / from address |
| `SLOC_SMTP_PASS` | SMTP password or app password |

### 5f. Bitbucket credentials (optional)

If using Bitbucket as the SCM:

| Field | Value |
|-------|-------|
| Kind | **Username with password** |
| Username | Your Bitbucket username |
| Password | A Bitbucket app password with repo-read scope |
| ID | `bitbucket-credentials` |

---

## 6. Configure the CSP header (HTML report viewer)

By default, Jenkins's Content Security Policy blocks the inline styles and scripts
in the oxide-sloc HTML report.  Fix this with an init script:

1. Find your `$JENKINS_HOME`:
   - Docker: `/var/jenkins_home`
   - Native: `/var/lib/jenkins` (or wherever Jenkins is installed)

2. Create the `init.groovy.d` directory if it doesn't exist:
   ```bash
   sudo mkdir -p $JENKINS_HOME/init.groovy.d
   ```

3. Copy the provided Groovy script:
   ```bash
   sudo cp ci/jenkins/init.groovy.d/relax-csp.groovy $JENKINS_HOME/init.groovy.d/
   ```
   Or paste this content into a new file at that path:
   ```groovy
   // $JENKINS_HOME/init.groovy.d/relax-csp.groovy
   import hudson.model.Hudson
   System.setProperty(
     "hudson.model.DirectoryBrowserSupport.CSP",
     "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:;"
   )
   ```

4. **Restart Jenkins** for the init script to take effect:
   - Docker: `docker restart jenkins`
   - Native: `sudo systemctl restart jenkins`

> **Without this step**, the SLOC Report and Coverage Report HTML pages will render
> unstyled (plain text-like).  Everything else still works.

---

## 7. Create the pipeline job

1. From the Jenkins home page, click **"+ New Item"** in the left sidebar.

2. In the **"Enter an item name"** field, type: `oxide-sloc`

3. Select **"Pipeline"** from the list of item types (the blue icon with connected circles).

4. Click **OK**.

---

## 8. Configure the pipeline job

You are now in the job configuration screen.  Work through each section top-to-bottom.

### 8a. General

| Setting | Value |
|---------|-------|
| Description | `oxide-sloc SLOC analysis pipeline — scans source repositories and produces HTML, JSON, and PDF reports with build-over-build trend data.` |
| ✓ Discard old builds | Check this box |
| → Max # of builds to keep | `25` |
| → Max # of builds with artifacts to keep | `10` |

### 8b. Build Triggers (optional)

If you want the pipeline to trigger automatically:

- **Poll SCM**: Enter a cron expression (e.g., `H/5 * * * *` = every 5 minutes).
- **GitHub hook trigger**: Check this box and configure the GitHub webhook at
  `https://<your-jenkins-url>/github-webhook/`.
- Leave all triggers unchecked if you prefer to trigger builds manually.

### 8c. Pipeline definition

| Setting | Value |
|---------|-------|
| Definition | **Pipeline script from SCM** |
| SCM | **Git** |
| Repository URL | `https://github.com/oxide-sloc/oxide-sloc.git` (or your fork/mirror URL) |
| Credentials | Leave as `- none -` for public repos; select SSH or username/password credentials for private repos |
| Branch Specifier | `*/main` |
| Script Path | `Jenkinsfile` |
| ✓ Lightweight checkout | Check this box |

> **Air-gapped / local repo:** Use `file:///absolute/path/to/oxide-sloc` as the
> Repository URL for a locally cloned copy.

### 8d. Save

Click **Save** at the bottom of the page.

---

## 9. Seed the parameters form (first build)

Jenkins discovers the `parameters {}` block in the Jenkinsfile only after running it
once.  The first build must run **without parameters** to register them.

1. On the job page, click **"Build Now"** in the left sidebar.
   The first build runs with defaults (`SKIP_WEB_CHECK` defaults to true for a fresh
   install). It should complete successfully — Analyze runs against
   `tests/fixtures/basic` which exists in the repository, and the Web UI check stage
   is skipped by default.

2. Wait for the build to complete. It should be **green** on the first run with default settings.

3. Refresh the job page.  The left sidebar now shows **"Build with Parameters"**.

From this point on, all 40+ configuration parameters are visible in the build form.

---

## 10. Run a real build

1. Click **"Build with Parameters"** in the left sidebar.

2. The build form opens with all parameters grouped by function.
   Adjust at minimum:

   | Parameter | What to set |
   |-----------|------------|
   | `REPO_URL` | URL of the repository you want to scan |
   | `SCAN_PATH` | Path within the repository to analyze (e.g., `src` or `.`) |
   | `REPORT_TITLE` | A descriptive title for the HTML report |
   | `GENERATE_HTML` | Check to produce an HTML report (recommended) |
   | `SKIP_SONAR` | Check to skip SonarQube if you haven't set up a server yet |
   | `SKIP_WEB_CHECK` | Check if port 4317 is not available on the agent |

3. Click **Build**.

4. Watch the build progress in the **Stage View** on the job page.
   Click any stage block to see its console output.

---

## 11. Verify all features

After a successful build, confirm each feature is wired correctly:

### SLOC Report (HTML Publisher)
- The left sidebar shows a **"SLOC Report — &lt;SLOC_PROJECT&gt;"** link.
  The slug is derived from `SCAN_PATH` basename (e.g. `"SLOC Report — basic"` for the
  default `tests/fixtures/basic`). If `SLOC_PROJECT` is set explicitly, that exact string
  is used as the slug.
- Clicking it opens the HTML report in the browser.
- If it shows unstyled content, revisit [Step 6](#6-configure-the-csp-header-html-report-viewer).

### Build Dashboard (standalone, no-plugin fallback)
- A second sidebar link, **"Build Dashboard — &lt;SLOC_PROJECT&gt;"**, is published from
  `ci/jenkins/generate-dashboard.py`. This is a self-contained HTML file that works even
  on Jenkins instances where the Plot/JUnit/Coverage plugins are absent.
- Both sidebar links use Jenkins' em-dash URL encoding: the `—` character becomes
  `_e28094_` in the path (e.g. `/job/<JOB>/<N>/SLOC_20Report_20_e28094_20basic/`).
  Bookmarks from a pre-15b0a27e installation (which used `/SLOC_20Report/`) will return
  404 — update them once after upgrading.

### Trend charts (Plot plugin)
- The job page shows **"SLOC Trends"** charts below the build history.
- Charts include: "SLOC totals over time", "Per-language code lines".
- After 2+ builds, trend lines appear.
- The "Line coverage % over time" chart appears after a build with `COVERAGE_STANDALONE` enabled.

### Test results (JUnit plugin — nextest only)
- To enable: set `TEST_RUNNER = cargo-nextest` and `PUBLISH_TEST_RESULTS = true`.
- Requires cargo-nextest on the agent (see [Step 13](#13-optional-agent-setup--cargo-nextest-junit-test-results)).
- After a nextest build, the left sidebar shows a **"Test Result"** link.
- The job page shows a test trend chart.

### Coverage Report (HTML Publisher — cargo-llvm-cov only)
- To enable: check `COVERAGE_STANDALONE`.
- Requires cargo-llvm-cov on the agent (see [Step 14](#14-optional-agent-setup--cargo-llvm-cov-coverage)).
- After a successful coverage build, the left sidebar shows a **"Coverage Report"** link.
- The job page shows a "Line coverage % over time" trend chart.

### Build description
- The build list shows a description line like:
  ```
  scan=src  code=12543  files=87  comments=1204  blank=987  tests=42 fail=0 err=0  coverage=74.2%
  ```
  This confirms all metadata was correctly read from the build output.

### Archived artifacts
- Click the build number → **"Build Artifacts"** to see all archived files:
  - `target/release/oxide-sloc` (the compiled binary)
  - `ci-out/result.json`, `ci-out/report.html` (scan outputs)
  - `ci-out/test-results/` (JUnit XML and/or raw test output)
  - `ci-out/coverage/` (lcov.info, sonar-coverage.xml, html/)
  - `ci-out/summary.csv`, `ci-out/per_language.csv`, `ci-out/coverage.csv` (trend CSVs)

---

## 12. Agent setup — Rust toolchain

The Rust compiler is **not** bundled in the repository.  The pipeline downloads or
copies it to a persistent cache directory (`~/.rust-cache/`) on first use.

### Option A — Internet-connected agent (simplest)

No setup needed.  The Jenkinsfile's Setup stage downloads the Rust toolchain
automatically via `rustup` on the first build.  Subsequent builds use the cached
toolchain.

### Option B — Pre-seed the cache (faster first build)

Run the cache-seeding script once on the agent before the first build:

```bash
bash ci/jenkins/install-rust-cache.sh
```

This installs the toolchain pinned in `rust-toolchain.toml` into `~/.rust-cache/`
so the first pipeline build skips the download entirely.

### Option C — Docker agent (recommended for isolation)

Build the provided agent image once and run all builds inside it:

```bash
# Build the image (includes the pinned Rust toolchain at /opt/rust-toolchain)
docker build -t jenkins-oxide-sloc:latest -f ci/jenkins/Dockerfile.agent .
```

In Jenkins, configure an agent (or the built-in node) to run containers from this image,
or update `agent { docker { image 'jenkins-oxide-sloc:latest' } }` in the Jenkinsfile.

### Option D — Air-gapped bundle (no internet on agent)

Bundle the toolchain on a networked machine and commit the archive:

```bash
bash ci/jenkins/bundle-rust-toolchain.sh
# Produces: rust-toolchain-bundle.tar.xz + rust-toolchain-bundle.tar.xz.sha256
# Split before committing (bundle is typically 200-350 MB):
split -b 45m rust-toolchain-bundle.tar.xz rust-toolchain-bundle.tar.xz.
rm rust-toolchain-bundle.tar.xz
git add rust-toolchain-bundle.tar.xz.* rust-toolchain-bundle.tar.xz.sha256
git commit -m "chore: add rust toolchain bundle for air-gapped agents"
```

The Jenkinsfile Setup stage detects and verifies this file automatically.

---

## 13. Optional agent setup — cargo-nextest (JUnit test results)

Enable `TEST_RUNNER = cargo-nextest` only after installing nextest on the agent.

```bash
# Install cargo-nextest (requires Rust toolchain already installed)
cargo install cargo-nextest

# Verify
cargo nextest --version
```

For air-gapped agents, nextest can be installed from the vendor archive if it was
included when the archive was generated.  See `ci/tools/Cargo.toml` for adding it.

**What you get after enabling:**
- JUnit XML at `<OUTPUT_SUBDIR>/test-results/junit.xml` archived with every build.
- **"Test Result"** sidebar link on each build with pass/fail/skip counts.
- Test trend chart on the job page (tests over time).
- Full stack traces on failures via `RUST_BACKTRACE=1` (always enabled in the Unit tests stage).
- Retry of flaky tests once before marking as failed (configured in `.config/nextest.toml`).

---

## 14. Optional agent setup — cargo-llvm-cov (coverage)

Enable `COVERAGE_STANDALONE` only after installing cargo-llvm-cov on the agent.

```bash
# Install cargo-llvm-cov
cargo install cargo-llvm-cov

# Install the required LLVM tools component
rustup component add llvm-tools-preview

# Verify
cargo llvm-cov --version
```

For air-gapped agents, cargo-llvm-cov is vendored in `ci/tools/Cargo.toml`.
Install it offline with:

```bash
cargo install --offline cargo-llvm-cov
rustup component add llvm-tools-preview
```

**What you get after enabling `COVERAGE_STANDALONE`:**
- LCOV file (`lcov.info`) and Cobertura XML (`sonar-coverage.xml`) archived per build.
- Browsable HTML coverage report under `coverage/html/` archived per build.
- **"Coverage Report"** sidebar link on each build showing the HTML report.
- "Line coverage % over time" trend chart on the job page.
- Optional threshold gate: set `COVERAGE_THRESHOLD` to a number (e.g., `60`) to fail
  the build if line coverage drops below that percentage.
- When `GENERATE_COVERAGE` is also enabled, the SonarQube stage reuses the coverage
  data from this stage — tests run only once.

---

## 15. Troubleshooting

### "Build with Parameters" not showing after first build

The first build must **complete successfully through the Checkout and Setup stages**
for Jenkins to parse the Jenkinsfile.  If it failed at Checkout (e.g., wrong repo URL),
fix the SCM configuration under **Configure → Pipeline → Repository URL** and run
**Build Now** again.

### HTML report renders unstyled

The Jenkins CSP header is blocking inline styles.  Follow [Step 6](#6-configure-the-csp-header-html-report-viewer)
to deploy `relax-csp.groovy` and restart Jenkins.

### "vendor.tar.xz not found" error

The repository was cloned from a branch or tag that predates the vendor archive commit.
Ensure the `main` branch is checked out.  If using a local clone, run:

```bash
git pull origin main
ls -lh vendor.tar.xz vendor.tar.xz.sha256
```

### "cargo: command not found"

The Rust toolchain is not on the agent's `PATH`.  Check:
1. That the Setup stage completed (look for `rustup show` output in the console).
2. That `CARGO_HOME` and `RUSTUP_HOME` are pointed at a writable directory on the agent.
3. For Docker builds: that the container has write access to `$HOME/.rust-cache/`.

### "cargo-nextest not found"

Install nextest on the agent (see [Step 13](#13-optional-agent-setup--cargo-nextest-junit-test-results))
or switch `TEST_RUNNER` back to `cargo-test`.

### "cargo llvm-cov not found"

Install cargo-llvm-cov on the agent (see [Step 14](#14-optional-agent-setup--cargo-llvm-cov-coverage))
or uncheck `COVERAGE_STANDALONE`.

### SonarQube analysis not running

The SonarQube pipeline stage was removed from the Jenkinsfile.  SonarQube scans
are now run externally via the scripts in `ci/sonar/`, driven by the `SONAR_URL`
and `SONAR_TOKEN` environment variables.  See `docs/sonarqube-manual-setup.md`
for the current setup instructions.  There is no `SKIP_SONAR` parameter in the
current Jenkinsfile.

### Plot charts not appearing

The Plot plugin must be installed and the first **two** builds must complete before
trend data is visible (one data point does not make a chart).  Check that the plugin
is installed: **Manage Jenkins → Plugins → Installed plugins** → filter for "plot".

### "COVERAGE GATE FAILED" — build fails on coverage threshold

Your line coverage is below the `COVERAGE_THRESHOLD` value.  Either:
- Lower the threshold, or
- Improve test coverage, or
- Set `COVERAGE_THRESHOLD = 0` to disable the gate.

The console output shows the exact percentage and threshold for diagnosis.
