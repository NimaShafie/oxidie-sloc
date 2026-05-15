# Jenkins job bootstrap

> **New to Jenkins?** See `docs/jenkins-manual-setup.md` for a complete step-by-step
> guide to creating the pipeline through the Jenkins web UI with no CLI required.
> This file covers the CLI bootstrap path for operators who prefer scripted setup.

## Operator workflow (overview)

1. `cp ci/jenkins/.env.example ci/jenkins/.env` — fill in `JENKINS_TOKEN`
2. _(Recommended)_ Pre-populate the agent rust-cache: run `bash ci/jenkins/install-rust-cache.sh` or build the Docker agent image from `ci/jenkins/Dockerfile.agent`. On air-gapped agents this step is required; on network-connected agents Rust downloads at runtime.
3. `set -a; source ci/jenkins/.env; set +a && bash ci/jenkins/preflight.sh` — all checks must pass
4. Run the `createItem` curl (Step 1 below)
5. Run the seed-build curl (Step 2 below)

On a network-connected agent, step 2 is optional.

## New pipeline features

The Jenkinsfile now supports three additional capability tiers beyond the basic SLOC scan.
Enable each tier by setting the corresponding build parameters.

### Unit test results (JUnit)

Set `TEST_RUNNER = cargo-nextest` and `PUBLISH_TEST_RESULTS = true`.

Requires `cargo-nextest` on the agent:
```bash
cargo install cargo-nextest
```

What you get:
- JUnit XML written to `<OUTPUT_SUBDIR>/test-results/junit.xml` and archived.
- **"Test Result"** sidebar link on each build with pass/fail/skip counts.
- Test trend chart on the job page.
- `RUST_BACKTRACE=1` always set — full stack traces on panics.
- Transient test failures retried once (configured in `.config/nextest.toml`).

Use `TEST_FAIL_FAST = true` to abort on the first failure for faster feedback.

### Standalone code coverage

Check `COVERAGE_STANDALONE`.

Requires `cargo-llvm-cov` on the agent (vendored in `ci/tools/Cargo.toml`):
```bash
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview
```

What you get:
- LCOV (`lcov.info`) and Cobertura XML (`sonar-coverage.xml`) archived per build.
- Browsable HTML report archived under `coverage/html/` per build.
- **"Coverage Report"** sidebar link on each build.
- "Line coverage % over time" trend chart on the job page.
- Optional threshold gate: set `COVERAGE_THRESHOLD = 60` to fail builds below 60 % coverage.
- When `GENERATE_COVERAGE` is also enabled, coverage runs once and is reused by SonarQube.

### Artifact repository push

Set `ARTIFACT_REPO_TYPE` to any backend (artifactory, nexus, s3, minio, azure-blob, generic-http)
and fill in `ARTIFACT_REPO_URL`.  Add credentials `SLOC_ARTIFACT_REPO_USER` /
`SLOC_ARTIFACT_REPO_PASS` in Jenkins for authenticated repositories.

---

---

## Obtaining credentials

### Initial admin password

If Jenkins was just installed and has never been unlocked:

**Native install (systemd / RPM / DEB package):**
```bash
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
# some installs use /var/jenkins_home instead:
sudo cat /var/jenkins_home/secrets/initialAdminPassword
```

**Docker install:**
```bash
docker exec <container-name-or-id> cat /var/jenkins_home/secrets/initialAdminPassword
```

Paste this password into the Jenkins setup wizard at `http://<host>:8080/`.

#### If initialAdminPassword is gone

After first-run setup completes, Jenkins deletes that file. If you've also lost your token (e.g. you re-cloned and `ci/jenkins/.env` is gone), use one of:

- **Browser:** sign in at `http://<host>:8080/` with your admin password → click your username (top-right) → **Configure** → scroll to **API Token** → **Add new Token**. (The direct URL `/user/<id>/configure` is gone in some recent LTS builds; use the dropdown link instead.)
- **REST (Path B below):** the same admin password works — no `initialAdminPassword` needed.
- **Reset admin password (last resort):** `docker exec -u root <container> bash -c 'echo "admin:NEW" | chpasswd'` does NOT work for Jenkins — the password lives in `/var/jenkins_home/users/admin_*/config.xml` as a hashed `passwordHash`. To reset it, edit that file with a known hash (or run Jenkins with `-Djenkins.install.runSetupWizard=true` and reuse `initialAdminPassword`). Avoid this unless the password is genuinely lost.

### Minting a long-lived API token

After the initial setup wizard is complete:

1. Open **Manage Jenkins → Users → admin → Configure**
2. Scroll to **API Token → Add new Token**
3. Give it a name (e.g. `bootstrap-token`) and click **Generate**
4. **Copy the token now** — it is shown only once and cannot be retrieved later

#### Path B — mint via REST

If you prefer not to use the GUI, you can mint the token via the Jenkins REST API. The cookie jar is required — the CSRF crumb is only honored within the same session that issued it.

```bash
# Pre-req: the admin password (initialAdminPassword or the configured one).
JENKINS_URL=http://10.0.0.8:8080
JENKINS_USER=admin
read -rsp "Jenkins admin password: " JENKINS_PASS
echo
# Read at the prompt — keeps the password out of shell history.

cookies=$(mktemp)
crumb=$(curl -sS -c "$cookies" -u "$JENKINS_USER:$JENKINS_PASS" \
  "$JENKINS_URL/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")

curl -sS -b "$cookies" -u "$JENKINS_USER:$JENKINS_PASS" -H "$crumb" \
  -X POST --data 'newTokenName=bootstrap-token' \
  "$JENKINS_URL/user/$JENKINS_USER/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken"
# → JSON containing tokenValue. Copy that value into JENKINS_TOKEN in ci/jenkins/.env.
rm -f "$cookies"
```

#### Path C — mint via Groovy init (host-root path, no password needed)

Use this when you have shell (or Docker exec) access to the Jenkins host but have lost both the admin password and the `initialAdminPassword` file. It requires no UI session and takes ~30 seconds.

**Step 1 — write the init script**

```bash
# Docker:
docker exec <container-name> mkdir -p /var/jenkins_home/init.groovy.d
docker exec -i <container-name> tee /var/jenkins_home/init.groovy.d/mint-token.groovy <<'EOF'
import jenkins.model.Jenkins
import jenkins.security.ApiTokenProperty

def admin = Jenkins.instance.getUser('admin')
def tokenProp = admin.getProperty(ApiTokenProperty.class)
def result = tokenProp.tokenStore.generateNewToken('bootstrap-token')
new File('/var/jenkins_home/bootstrap-token.txt').text = result.plainValue
EOF

# Native (adjust JENKINS_HOME if different):
sudo tee $JENKINS_HOME/init.groovy.d/mint-token.groovy <<'EOF'
import jenkins.model.Jenkins
import jenkins.security.ApiTokenProperty

def admin = Jenkins.instance.getUser('admin')
def tokenProp = admin.getProperty(ApiTokenProperty.class)
def result = tokenProp.tokenStore.generateNewToken('bootstrap-token')
new File('/var/jenkins_home/bootstrap-token.txt').text = result.plainValue
EOF
```

**Step 2 — restart Jenkins**

```bash
# Docker:
docker restart <container-name>
# Native:
sudo systemctl restart jenkins
```

**Step 3 — read the token and clean up**

```bash
# Docker:
TOKEN=$(docker exec <container-name> cat /var/jenkins_home/bootstrap-token.txt)
docker exec <container-name> rm /var/jenkins_home/bootstrap-token.txt \
    /var/jenkins_home/init.groovy.d/mint-token.groovy
echo "Token: $TOKEN"

# Native:
TOKEN=$(sudo cat $JENKINS_HOME/bootstrap-token.txt)
sudo rm $JENKINS_HOME/bootstrap-token.txt \
    $JENKINS_HOME/init.groovy.d/mint-token.groovy
echo "Token: $TOKEN"
```

**Step 4 — store it**

Copy the printed token value into `JENKINS_TOKEN` in `ci/jenkins/.env`.

> **Important:** delete `mint-token.groovy` immediately after reading the token. Init scripts in `init.groovy.d/` run on every Jenkins restart — leaving the file in place regenerates and overwrites the token file on the next reboot.

### Storing credentials locally

```bash
cp ci/jenkins/.env.example ci/jenkins/.env
# Then open ci/jenkins/.env and fill in JENKINS_TOKEN with the value from above.
```

`ci/jenkins/.env` is listed in `.gitignore` — it will never be committed.

**URL note:** LAN/remote addresses (e.g., `http://10.0.0.8:8080`) are valid substitutions for `http://localhost:8080`. Strip any trailing slash — `${JENKINS_URL}/createItem` would otherwise produce `//createItem`, which some reverse proxies reject.

**Job name:** Use `oxide-sloc` for the SCM-driven job created from `ci/jenkins/job-config.xml`. Use `oxide-sloc-manual` only if you also intend to maintain a hand-edited copy of the pipeline in the same Jenkins instance and need to disambiguate.

---

## Step 0 — Pre-flight check

Run this before the `createItem` call. It verifies reachability, authentication, plugin presence, and that no conflicting job exists:

```bash
set -a; source ci/jenkins/.env; set +a && bash ci/jenkins/preflight.sh
```

All lines must print `[ok]`. Fix any `[fail]` before continuing.

If a `[info]` line reports that `hudson.model.DirectoryBrowserSupport.CSP` is at the default value, re-run with `--install-csp` to copy `relax-csp.groovy` into the running Jenkins container and restart it (requires Docker on the same host as Jenkins):

```bash
set -a; source ci/jenkins/.env; set +a && bash ci/jenkins/preflight.sh --install-csp
```

---

## Installing plugins (air-gapped — recommended)

All required plugins can be bundled for air-gapped installs into `jenkins-plugins.tar.xz`
following the same model as `vendor.tar.xz` for Rust crates.
Generate and commit it once (see below), then every `git clone` is fully offline.

The full plugin list is in `ci/jenkins/plugins.txt`.

### One-time bundle generation (networked machine, run once)

Run this on any machine that has Docker and internet access, then commit the output:

```bash
bash ci/jenkins/bundle-jenkins-plugins.sh
# Outputs: jenkins-plugins.tar.xz + jenkins-plugins.tar.xz.sha256
# If the archive exceeds 45 MB, the script will print split instructions.

git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
git commit -m "ci: bundle Jenkins plugins for air-gapped install"
```

The bundle script downloads all plugins **and their full transitive dependency trees**
using the official `jenkins-plugin-cli` that ships with `jenkins/jenkins:lts-jdk21`.
After committing, every `git clone` has everything needed for a completely offline setup.

Re-run whenever `ci/jenkins/plugins.txt` changes (added or removed plugins) and
commit both files atomically — the controller Dockerfile and install script both
verify the SHA-256 checksum before extracting.

---

### Path A — Docker controller image (recommended for Docker setups)

`ci/jenkins/Dockerfile.controller` builds a Jenkins controller with all plugins
pre-installed from `jenkins-plugins.tar.xz`.  The resulting image needs no network
access at runtime and never contacts the Jenkins update center.

```bash
# Build once after generating the bundle:
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

In `docker-compose.yml`, replace `image: jenkins/jenkins:lts` with:

```yaml
build:
  context: .
  dockerfile: ci/jenkins/Dockerfile.controller
image: jenkins-oxide-sloc-controller:latest
```

Rebuild the image whenever `jenkins-plugins.tar.xz` is updated.

---

### Path B — Install into a running Jenkins instance

Use this for native / systemd Jenkins or an already-running Docker container
where you cannot rebuild the image.

```bash
# From the repo root on the Jenkins host (or inside the container):
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

The install script verifies the checksum, extracts all `.hpi` files to
`$JENKINS_HOME/plugins/`, pins each plugin (prevents update-center replacement),
and optionally restarts Jenkins.

To install without restarting (then restart manually):
```bash
bash ci/jenkins/install-jenkins-plugins.sh
# Restart Jenkins manually — Docker:
docker restart <container-name>
# Native:
sudo systemctl restart jenkins
```

To install to a custom path (e.g., inside a Dockerfile `RUN` step):
```bash
bash ci/jenkins/install-jenkins-plugins.sh \
    --target-dir /usr/share/jenkins/ref/plugins
```

---

### Path C — Online install (internet-connected Jenkins)

Only use this when the machine has internet access and a running Jenkins instance.

**Docker:**
```bash
docker exec -u root <container> jenkins-plugin-cli \
  --plugin-download-directory /var/jenkins_home/plugins \
  --plugins $(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' ci/jenkins/plugins.txt \
              | awk '{print $1}' | tr '\n' ' ')
docker restart <container>
```

Without `--plugin-download-directory`, plugins land in `/usr/share/jenkins/ref/plugins/`
which only seeds a brand-new `JENKINS_HOME` on first start — a running instance never
picks them up.  The flag redirects downloads directly into the active plugins directory.

**Native (Jenkins CLI jar):**
```bash
set -a; source ci/jenkins/.env; set +a
curl -sS -o jenkins-cli.jar "${JENKINS_URL}/jnlpJars/jenkins-cli.jar"
java -jar jenkins-cli.jar -s "${JENKINS_URL}" -auth "${JENKINS_USER}:${JENKINS_TOKEN}" \
    install-plugin $(grep -Ev '^[[:space:]]*#|^[[:space:]]*$' ci/jenkins/plugins.txt \
                     | awk '{print $1}')
java -jar jenkins-cli.jar -s "${JENKINS_URL}" -auth "${JENKINS_USER}:${JENKINS_TOKEN}" \
    safe-restart
```

---

### Plugin verification

`ci/jenkins/preflight.sh` check (c) queries the running Jenkins plugin manager and
prints `[ok]` / `[fail]` per plugin in `ci/jenkins/plugins.txt`:

```bash
set -a; source ci/jenkins/.env; set +a
bash ci/jenkins/preflight.sh
```

Exit code 0 = all plugins active and enabled.  Non-zero = at least one missing or disabled.

---

## Option A — Job DSL

See `ci/jenkins/seed-job.groovy`.

---

## Option B — CLI bootstrap

### Step 1 — Create the job

```bash
set -a; source ci/jenkins/.env; set +a

# Render the job XML with your REPO_URL substituted (path printed to stderr)
JOB_XML=$(bash ci/jenkins/render-job-config.sh)

CRUMB=$(curl -sS -u "${JENKINS_USER}:${JENKINS_TOKEN}" \
    "${JENKINS_URL}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)")

curl -sS -u "${JENKINS_USER}:${JENKINS_TOKEN}" \
    -H "${CRUMB}" -H "Content-Type: application/xml" \
    --data-binary @"${JOB_XML}" \
    "${JENKINS_URL}/createItem?name=${JOB_NAME}"
```

A 200 response with an empty body means the job was created successfully. A 400 with `job already exists` means the job name is taken — choose a different `JOB_NAME`.

### Step 2 — Trigger the first (seed) build

```bash
curl -sS -X POST -u "${JENKINS_USER}:${JENKINS_TOKEN}" \
    "${JENKINS_URL}/job/${JOB_NAME}/build"
```

The first build runs with no parameters — Jenkins uses it to discover the `parameters {}` block in the Jenkinsfile. From build #2 onward, **Build with Parameters** in the left-hand sidebar shows the full configurable form.

---

## Setting the artifact-viewer CSP

The HTML report requires the Jenkins artifact viewer to allow inline styles. The recommended approach is to drop `ci/jenkins/init.groovy.d/relax-csp.groovy` into `$JENKINS_HOME/init.groovy.d/` before starting Jenkins:

```bash
cp ci/jenkins/init.groovy.d/relax-csp.groovy $JENKINS_HOME/init.groovy.d/
# Then restart Jenkins.
```

This sets the CSP property at startup without requiring in-process script approval. For external origins (GitHub Pages, S3), control the `Content-Security-Policy` response header directly on that service instead.

---

## Bitbucket integration

### Required plugins

- **Bitbucket Branch Source** (`bitbucket`) — enables Bitbucket multibranch projects
- **Bitbucket Build Status Notifier** (`bitbucket-build-status-notifier`) — posts commit statuses to Bitbucket

### Webhook URL

Configure a webhook in Bitbucket pointing to:
```
<JENKINS_URL>/bitbucket-hook/
```

For Bitbucket Server (Data Center), navigate to **Repository Settings → Webhooks → Add webhook** and set the URL above. For Bitbucket Cloud, use **Repository Settings → Webhooks**.

### Environment variables

Set these in `ci/jenkins/.env` (see `.env.example`):

```bash
export BITBUCKET_URL=https://bitbucket.example.com   # Server/Data Center URL
export BITBUCKET_PROJECT=OXIDE                        # Project key
export BITBUCKET_REPO=oxide-sloc                      # Repository slug
```

### Using Bitbucket as the SCM source

In `ci/jenkins/seed-job.groovy`, uncomment and fill in the `bitbucketServer { }` block:

```groovy
bitbucketServer {
    serverUrl(System.getenv('BITBUCKET_URL') ?: 'https://bitbucket.example.com')
    credentialsId('bitbucket-credentials')
    projectKey(System.getenv('BITBUCKET_PROJECT') ?: 'OXIDE')
    repositoryName(System.getenv('BITBUCKET_REPO') ?: 'oxide-sloc')
}
```

Add a credential with ID `bitbucket-credentials` (username + password or SSH key) via **Manage Jenkins → Credentials**.
