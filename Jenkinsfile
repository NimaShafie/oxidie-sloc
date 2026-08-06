/*
 * oxide-sloc canonical Jenkins pipeline.
 *
 * This is the entry point used by ci/jenkins/job-config.xml and seed-job.groovy.
 * It is intentionally kept thin: helper logic lives in ci/jenkins/pipeline-helpers.groovy
 * and is loaded after checkout so that each function compiles as a separate class,
 * keeping every generated method well under the JVM 64 KB bytecode limit.
 *
 * Do NOT add def functions or large sh-heredocs here — put them in pipeline-helpers.groovy
 * or in a dedicated ci/jenkins/*.sh script and call it with sh 'bash ci/jenkins/script.sh'.
 *
 * Pipeline-of-Pipelines usage:
 *   From an orchestrator pipeline, trigger this job with:
 *     build job: 'oxide-sloc', parameters: [
 *       string(name: 'REPO_URL',        value: 'https://...'),
 *       string(name: 'DOWNSTREAM_JOB',  value: 'next-pipeline'),
 *       string(name: 'ARTIFACT_PATH',   value: '')
 *     ], wait: true
 *   This pipeline will trigger DOWNSTREAM_JOB on success, passing back
 *   UPSTREAM_JOB, UPSTREAM_BUILD, and ARTIFACT_PATH.
 */

def h   // loaded after Checkout; all runXxx() calls below delegate here

// ── Pipeline ───────────────────────────────────────────────────────────────
pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        // Bound server storage on BOTH count and age. Build records (logs +
        // published HTML reports) are capped at 20 builds / 30 days; the heavier
        // archived artifacts (JSON/HTML/PDF/XLSX/sub-reports) are pruned harder —
        // last 5 builds / 14 days — since only the latest matter for review and
        // trend history is preserved separately in the persistent CSV.
        buildDiscarder(logRotator(
            numToKeepStr:         '20',
            daysToKeepStr:        '30',
            artifactNumToKeepStr: '5',
            artifactDaysToKeepStr: '14'
        ))
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        // NOTE: ansiColor('xterm') was intentionally removed. It is a parse-time
        // hard dependency on the non-default AnsiColor plugin (a missing options
        // directive can't be try/catch'd), and it only colorized console output.
        // Dropping it lets the pipeline run on a controller where AnsiColor isn't
        // installed. To restore coloured logs, install AnsiColor and re-add it.
    }

    // ── Build parameters ──────────────────────────────────────────────────────
    // All fields appear as form controls in Jenkins → "Build with Parameters".
    // The first build of a Pipeline-from-SCM job is unparameterized — Jenkins
    // only discovers the parameters{} block after running Jenkinsfile once.
    // Run the first build with no arguments to seed the form; from build #2
    // onward, "Build with Parameters" in the sidebar shows the full form.
    //
    // Ordered from most-frequently changed (top) to rarely touched (bottom).
    // Artifact repo config and pipeline-chaining params are last so the form
    // stays compact for normal scan runs.
    parameters {

        // ═══════════════════════════════════════════════════════════════════════
        //  WHAT TO SCAN — point this at any existing repo and hit Build.
        //  GitHub / GitLab / Bitbucket / local all work (it's a plain git clone).
        //  Private repo? also set TARGET_CREDENTIALS_ID. Leave TARGET_REPO_URL
        //  blank to scan this tooling repo itself (self-CI / demo).
        //  See docs: ci/jenkins/INTEGRATION.md
        // ═══════════════════════════════════════════════════════════════════════
        string(
            name:         'TARGET_REPO_URL',
            defaultValue: '',
            description:  'The repo to analyze — any Git URL (GitHub / GitLab / Bitbucket / ' +
                          'file:///local, https:// or ssh://). Blank = scan this tooling repo itself. ' +
                          'Cloned into ./_target; SCAN_PATH is resolved inside it.'
        )
        string(
            name:         'TARGET_REF',
            defaultValue: '',
            description:  'Branch, tag, or commit SHA to scan (blank = the repo default branch). ' +
                          'e.g. main, develop, v2.1.0, a3f9d2c'
        )
        string(
            name:         'TARGET_CREDENTIALS_ID',
            defaultValue: '',
            description:  'Jenkins credentials ID for cloning a PRIVATE target repo (a username + ' +
                          'personal-access-token, or an SSH key if TARGET_REPO_URL is an ssh:// URL). ' +
                          'Blank = public repo, or the agent already has git access. ' +
                          'Add one under Manage Jenkins > Credentials, then paste its ID here.'
        )
        string(
            name:         'SCAN_PATH',
            defaultValue: '',
            description:  'Subdirectory of the target repo to scan. BLANK = the whole repo (recommended). ' +
                          'Set e.g. "src" or "packages/api" for a subtree; absolute paths also work.'
        )

        // ═══════════════════════════════════════════════════════════════════════
        //  OPTIONAL — everything below is pre-set to oxide-sloc's application
        //  defaults. For a standard scan, ignore it all: set TARGET_REPO_URL above
        //  and hit Build. The checkbox just marks the boundary.
        //  (Jenkins' built-in form cannot truly collapse these fields without the
        //  Active Choices plugin — see ci/jenkins/MAINTENANCE.md for that option.)
        // ═══════════════════════════════════════════════════════════════════════
        booleanParam(
            name:         'CHANGE_DEFAULT_SCAN_SETTINGS',
            defaultValue: false,
            description:  'Leave UNCHECKED for a standard scan with oxide-sloc defaults — you only need ' +
                          'TARGET_REPO_URL above. Check it as a reminder when you intend to change any of ' +
                          'the optional parameters that follow (they are all pre-set to sensible defaults).'
        )

        // ── Optional — output naming ───────────────────────────────────────────
        string(
            name:         'REPO_URL',
            defaultValue: 'https://github.com/oxide-sloc/oxide-sloc.git',
            description:  '(optional) Tooling repo the scanner is built from — leave at the default ' +
                          '(or your fork). This is NOT the project to scan; use TARGET_REPO_URL for that.'
        )
        string(
            name:         'REPORT_TITLE',
            defaultValue: 'oxide-sloc CI Report',
            description:  '(optional) Title shown in the generated HTML and PDF reports.'
        )
        string(
            name:         'OUTPUT_SUBDIR',
            defaultValue: 'ci-out',
            description:  '(optional) Workspace sub-directory for generated artifacts (letters, digits, - _ / only).'
        )

        // ── Pipeline switches (optional) ───────────────────────────────────────
        booleanParam(
            name:         'SKIP_QUALITY_GATES',
            defaultValue: false,
            description:  'Skip the Format / Lint / Unit tests stage. ' +
                          'Useful for scan-only runs where code-quality enforcement is not needed.'
        )
        booleanParam(
            name:         'SKIP_WEB_CHECK',
            defaultValue: true,
            description:  'Skip the web UI health-check stage. ' +
                          'Use on agents without loopback access or where port 4317 is unavailable.'
        )
        // ── CI config preset ───────────────────────────────────────────────────
        choice(
            name:    'CI_PRESET',
            choices: ['default', 'none', 'strict', 'full-scope'],
            description: 'CI configuration preset loaded from the ci/ directory:\n' +
                         '  none        — no preset; individual flags below control everything\n' +
                         '  default     — balanced defaults, mirrors web UI defaults  (ci/sloc-ci-default.toml)\n' +
                         '  strict      — fail the pipeline if binary files are found  (ci/sloc-ci-strict.toml)\n' +
                         '  full-scope  — count everything including vendor and lockfiles  (ci/sloc-ci-full-scope.toml)'
        )

        // ── Output formats ─────────────────────────────────────────────────────
        booleanParam(
            name:         'GENERATE_HTML',
            defaultValue: true,
            description:  'Write an HTML report artifact and publish it via the HTML Publisher plugin. ' +
                          'Appears as "SLOC Report" in the left-hand build menu. ' +
                          'Requires the "HTML Publisher" plugin — see ci/jenkins/plugins.txt.'
        )
        booleanParam(
            name:         'GENERATE_PDF',
            defaultValue: true,
            description:  'Write a PDF report artifact alongside the HTML report. ' +
                          'Pure-Rust generation — no browser or external tool required on the agent. ' +
                          'When enabled, the "View PDF" button in the HTML report opens the archived PDF directly.'
        )

        // ── Analysis rules ─────────────────────────────────────────────────────
        choice(
            name:    'MIXED_LINE_POLICY',
            choices: ['code-only', 'code-and-comment', 'comment-only', 'separate-mixed-category'],
            description: 'How lines containing both code and an inline comment are classified. ' +
                         'Overridden by preset when CI_PRESET is not "none".\n' +
                         '  code-only               — count toward code total (default)\n' +
                         '  code-and-comment        — count toward both code and comment totals\n' +
                         '  comment-only            — count toward comment total only\n' +
                         '  separate-mixed-category — tracked in a dedicated "mixed" bucket'
        )
        booleanParam(
            name:         'DOCSTRINGS_AS_CODE',
            defaultValue: false,
            description:  'Count Python triple-quoted docstrings as code lines instead of comment lines.'
        )
        booleanParam(
            name:         'SUBMODULE_BREAKDOWN',
            defaultValue: true,
            description:  'Detect .gitmodules and emit per-submodule stats in the report.'
        )
        string(
            name:         'STYLE_COL_THRESHOLD',
            defaultValue: '80',
            description:  'Column-width threshold for Code Style N-col compliance reporting. ' +
                          'Supported values: 80, 100, 120. Controls the "N-Col Compliant" chip ' +
                          'in HTML/PDF reports and the style_col_compliant_pct metric in CI output.'
        )
        string(
            name:         'ACTIVITY_WINDOW',
            defaultValue: '90',
            description:  'Git Hotspots activity window in days (on by default). oxide-sloc runs one ' +
                          'git log pass over the last N days and ranks files by code lines x recent ' +
                          'commits in a Git Hotspots section (HTML/PDF) plus Commits/Last-changed ' +
                          'columns in CSV. Set 0 to disable. Requires SCAN_PATH to be a git checkout.'
        )
        booleanParam(
            name:         'FOLLOW_SYMLINKS',
            defaultValue: false,
            description:  'Follow symbolic links during file discovery.'
        )
        booleanParam(
            name:         'NO_IGNORE_FILES',
            defaultValue: false,
            description:  'Ignore .gitignore / .slocignore rules — scan everything under SCAN_PATH.'
        )
        string(
            name:         'ENABLED_LANGUAGES',
            defaultValue: '',
            description:  'Comma-separated language filter — restricts analysis to the listed languages. ' +
                          'Example: rust,python,javascript   (empty = all 60 supported languages)'
        )
        string(
            name:         'INCLUDE_GLOBS',
            defaultValue: '',
            description:  'Comma-separated include glob patterns. ' +
                          'Only files matching at least one pattern are analyzed. ' +
                          'Example: src/**/*.py,scripts/*.sh   (empty = all files)'
        )
        string(
            name:         'EXCLUDE_GLOBS',
            defaultValue: '',
            description:  'Comma-separated exclude glob patterns. ' +
                          'Files matching any pattern are skipped entirely. ' +
                          'Example: vendor/**,**/*.min.js   (empty = nothing excluded)'
        )

        // ── Git-ref comparison ─────────────────────────────────────────────────
        string(
            name:         'GIT_REF',
            defaultValue: '',
            description:  'Scan the repository at this specific git ref (branch, tag, or commit SHA). ' +
                          'Leave empty to scan HEAD (the checked-out commit). ' +
                          'When set, oxide-sloc creates a temporary worktree, scans it, then removes it. ' +
                          'Example: v1.4.0  or  refs/tags/v1.4.0  or  a3f9d2c'
        )
        string(
            name:         'COMPARE_TO_REF',
            defaultValue: '',
            description:  'Compare the GIT_REF scan against this baseline ref. ' +
                          'Produces a JSON/HTML diff report alongside the normal scan output. ' +
                          'Leave empty to skip comparison. Example: v1.3.7'
        )
        booleanParam(
            name:         'COMPARE_TO_PREV_TAG',
            defaultValue: false,
            description:  'Automatically detect the previous release tag (the one before GIT_REF or HEAD) ' +
                          'and use it as the baseline for comparison. Overrides COMPARE_TO_REF when set.'
        )

        // ── Test runner & results ──────────────────────────────────────────────
        choice(
            name:    'TEST_RUNNER',
            choices: ['cargo-test', 'cargo-nextest'],
            description: 'Test runner for the Unit tests stage. Default cargo-test so a fresh ' +
                         'agent with no extra tooling passes green. Switch to cargo-nextest to ' +
                         'get the "Test Result" view + trend (requires cargo-nextest on the ' +
                         'agent — see docs/jenkins-manual-setup.md Step 13). If cargo-nextest ' +
                         'is selected but is not on the agent and the offline install fails, ' +
                         'the stage falls back to cargo test and marks the build UNSTABLE ' +
                         '(yellow) so the missing JUnit report is visible.\n' +
                         '  cargo-test    — standard stable cargo test; console output only (no JUnit XML)\n' +
                         '  cargo-nextest — faster parallel runner with JUnit XML output (needs ' +
                         'cargo-nextest on the agent; "cargo install --locked cargo-nextest"). ' +
                         'Publishes the "Test Result" trend when PUBLISH_TEST_RESULTS is checked.'
        )
        booleanParam(
            name:         'PUBLISH_TEST_RESULTS',
            defaultValue: true,
            description:  'Publish JUnit XML test results to Jenkins (requires TEST_RUNNER = cargo-nextest). ' +
                          'Results appear as a "Test Result" sidebar link, per-build trend chart, and build badge. ' +
                          'Has no effect when TEST_RUNNER is "cargo-test" (no XML is generated).'
        )
        booleanParam(
            name:         'TEST_FAIL_FAST',
            defaultValue: false,
            description:  'Stop on the first test failure instead of running all tests to completion. ' +
                          'Useful for fast feedback on a known-broken area; leave unchecked to see all failures at once.'
        )

        // ── Standalone code coverage ───────────────────────────────────────────
        booleanParam(
            name:         'COVERAGE_STANDALONE',
            defaultValue: false,
            description:  'Run a dedicated Coverage stage. ' +
                          'Generates LCOV, Cobertura XML, and a browsable HTML coverage report. ' +
                          'The HTML report is published as a "Coverage Source" sidebar link. ' +
                          'Requires cargo-llvm-cov (preferred) or cargo-tarpaulin on the agent:\n' +
                          '  cargo install cargo-llvm-cov && rustup component add llvm-tools\n' +
                          'cargo-llvm-cov is vendored in ci/tools/Cargo.toml for air-gapped installs.'
        )
        string(
            name:         'COVERAGE_THRESHOLD',
            defaultValue: '0',
            description:  'Minimum line-coverage percentage required to pass the build (0 = disabled). ' +
                          'Only enforced when COVERAGE_STANDALONE is enabled. ' +
                          'Coverage percentage is derived from the LCOV lcov.info summary lines (LH / LF). ' +
                          'Example: 60  fails the build if fewer than 60 % of lines are covered.'
        )

        // ── Delivery / notifications ───────────────────────────────────────────
        string(
            name:         'WEBHOOK_URL',
            defaultValue: '',
            description:  'POST the JSON result to this URL after a successful scan (empty = skip). ' +
                          'Add SLOC_WEBHOOK_TOKEN as a Jenkins Secret Text credential for Bearer auth.'
        )
        string(
            name:         'EMAIL_RECIPIENTS',
            defaultValue: '',
            description:  'Comma-separated email addresses to receive the scan report (empty = skip). ' +
                          'Requires Jenkins Secret Text credentials: SLOC_SMTP_HOST, SLOC_SMTP_USER, SLOC_SMTP_PASS.'
        )

        // ── Artifact repository ────────────────────────────────────────────────
        // Push scan artifacts (JSON, HTML, PDF) to an external artifact repository
        // after each successful build.  Supported backends: JFrog Artifactory,
        // Sonatype Nexus 3 & 2, AWS S3, MinIO, Azure Blob Storage, and any server
        // that accepts HTTP PUT.  Set ARTIFACT_REPO_TYPE to "none" (the default) to
        // skip this stage entirely.
        //
        // Credentials — add these as Jenkins Secret Text credentials before use:
        //   SLOC_ARTIFACT_REPO_USER  username or access-key ID
        //   SLOC_ARTIFACT_REPO_PASS  password, API token, account key, or secret key
        //
        // The actual push is performed by ci/artifact-push.sh.  See that script and
        // docs/ci-integrations.md § Artifact Repository Integration for full details.
        choice(
            name:    'ARTIFACT_REPO_TYPE',
            choices: ['none', 'artifactory', 'nexus', 'nexus2', 's3', 'minio', 'azure-blob', 'generic-http'],
            description: 'Artifact repository backend to push scan results to after a successful build.\n' +
                         '  none         — skip artifact repository push (default)\n' +
                         '  artifactory  — JFrog Artifactory (REST PUT, user/pass or API key)\n' +
                         '  nexus        — Sonatype Nexus Repository Manager 3 (raw-format REST upload)\n' +
                         '  nexus2       — Sonatype Nexus Repository Manager 2 (PUT to content REST API)\n' +
                         '  s3           — Amazon S3 (requires aws CLI on the agent)\n' +
                         '  minio        — MinIO via aws CLI with custom --endpoint-url\n' +
                         '  azure-blob   — Azure Blob Storage (requires az CLI on the agent)\n' +
                         '  generic-http — any HTTP/HTTPS server accepting PUT requests'
        )
        string(
            name:         'ARTIFACT_REPO_URL',
            defaultValue: '',
            description:  'Base URL of the artifact repository (leave empty to skip push).\n' +
                          '  Artifactory : https://repo.example.com/artifactory/sloc-reports\n' +
                          '  Nexus 3     : https://nexus.example.com\n' +
                          '  Nexus 2     : https://nexus.example.com/nexus\n' +
                          '  S3 / MinIO  : s3://my-bucket\n' +
                          '  Azure Blob  : https://myaccount.blob.core.windows.net\n' +
                          '  Generic HTTP: https://artifacts.example.com/sloc'
        )
        string(
            name:         'ARTIFACT_REPO_PATH',
            defaultValue: 'oxide-sloc/${JOB_NAME}/${BUILD_NUMBER}',
            description:  'Path prefix / key prefix under which artifacts are stored in the repository. ' +
                          'The tokens ${JOB_NAME} and ${BUILD_NUMBER} are substituted at runtime. ' +
                          'For Nexus 3/2 this is the directory within the raw repository. ' +
                          'For Azure Blob this is the blob name prefix within the container. ' +
                          'Leading slashes are stripped automatically.'
        )
        string(
            name:         'ARTIFACT_REPO_EXTRA',
            defaultValue: '',
            description:  'Provider-specific extra configuration (leave empty when unused):\n' +
                          '  nexus / nexus2 — Nexus repository name (e.g. sloc-raw-hosted)\n' +
                          '  azure-blob     — storage container name (e.g. sloc-reports)\n' +
                          '  minio          — MinIO server endpoint URL (e.g. https://minio.internal:9000)\n' +
                          '  s3             — extra flags for aws s3 cp (e.g. --sse aws:kms)\n' +
                          '  others         — unused'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_JSON',
            defaultValue: true,
            description:  'Include result.json in the artifact repository push.'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_HTML',
            defaultValue: true,
            description:  'Include report.html in the artifact repository push ' +
                          '(only when GENERATE_HTML is checked).'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_PDF',
            defaultValue: false,
            description:  'Include report.pdf in the artifact repository push ' +
                          '(only when GENERATE_PDF is checked).'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_CSV',
            defaultValue: true,
            description:  'Include report.csv in the artifact repository push. ' +
                          'CSV is always generated — no separate output flag required.'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_XLSX',
            defaultValue: false,
            description:  'Include report.xlsx (Excel workbook) in the artifact repository push. ' +
                          'XLSX is always generated — no separate output flag required.'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_BINARY',
            defaultValue: false,
            description:  'Include the compiled oxide-sloc binary in the artifact repository push. ' +
                          'The binary is copied from target/release/ into the artifact directory before upload.'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_JUNIT',
            defaultValue: false,
            description:  'Include junit.xml test results in the artifact repository push. ' +
                          'Only applies when PUBLISH_TEST_RESULTS is checked and TEST_RUNNER is cargo-nextest.'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_COVERAGE',
            defaultValue: false,
            description:  'Include lcov.info and sonar-coverage.xml coverage reports in the push. ' +
                          'Only applies when COVERAGE_STANDALONE is checked.'
        )
        booleanParam(
            name:         'ARTIFACT_PUSH_DIFF',
            defaultValue: false,
            description:  'Include diff.json and diff.csv diff-comparison artifacts in the push. ' +
                          'Only applies when GIT_REF is set and a comparison ref is configured.'
        )
        booleanParam(
            name:         'ARTIFACT_GENERATE_MANIFEST',
            defaultValue: false,
            description:  'Generate and upload a SHA-256 checksum manifest (checksums.sha256) ' +
                          'listing the hash of every pushed artifact alongside the files themselves.'
        )

        // ── Atlassian Suite: Confluence + Bitbucket (optional) ─────────────────
        // Publish the finished report to Confluence and post a commit build-status
        // to Bitbucket after every build (see post{always} → runBitbucketNotify).
        // Both are fully opt-in and plugin-independent: they no-op (exit 0) when
        // their base URL or credential is absent, so leaving these blank changes
        // nothing.  The API tokens are NOT parameters — add them as Jenkins Secret
        // Text credentials so they are masked in the log:
        //   confluence-api-token   Confluence PAT (Server/DC) or Cloud API token
        //   bitbucket-build-token  Bitbucket HTTP access token / app password
        // The full HTML + PDF report is uploaded as a page attachment when present.
        // See docs/ci-integrations.md § Atlassian and
        // testing/atlassian-integration-test-plan.md.
        string(
            name:         'CONFLUENCE_BASE_URL',
            defaultValue: '',
            description:  '(optional) Confluence base URL. Server/DC: https://confluence.example.com ; ' +
                          'Cloud: https://your-domain.atlassian.net/wiki . Blank = skip Confluence publish.'
        )
        string(
            name:         'CONFLUENCE_USER',
            defaultValue: '',
            description:  '(optional) Confluence Cloud account email for basic auth (email:api-token). ' +
                          'Leave BLANK for Server/DC when confluence-api-token is a Personal Access Token (Bearer).'
        )
        string(
            name:         'CONFLUENCE_SPACE_KEY',
            defaultValue: '',
            description:  '(optional) Confluence space key to publish the summary page into (e.g. DEV). ' +
                          'Required for the Confluence publish to run.'
        )
        string(
            name:         'CONFLUENCE_PARENT_ID',
            defaultValue: '',
            description:  '(optional) Parent page ID to nest the report page under (blank = space root).'
        )
        string(
            name:         'CONFLUENCE_PAGE_TITLE',
            defaultValue: '',
            description:  '(optional) Page title to create/update. Blank = "oxide-sloc — <JOB_NAME>". ' +
                          'Re-using the same title updates the existing page (new version) instead of duplicating.'
        )
        string(
            name:         'BITBUCKET_BASE_URL',
            defaultValue: '',
            description:  '(optional) Bitbucket base URL for commit build-status. Server/DC: ' +
                          'https://bitbucket.example.com ; Cloud: https://api.bitbucket.org . Blank = skip.'
        )
        string(
            name:         'BITBUCKET_WORKSPACE',
            defaultValue: '',
            description:  '(optional) Bitbucket CLOUD workspace ID (Cloud only; ignored on Server/DC).'
        )
        string(
            name:         'BITBUCKET_REPO',
            defaultValue: '',
            description:  '(optional) Bitbucket CLOUD repository slug (Cloud only; ignored on Server/DC).'
        )
        string(
            name:         'BITBUCKET_USER',
            defaultValue: '',
            description:  '(optional) Bitbucket CLOUD username for app-password auth. When set, ' +
                          'notify-bitbucket.sh uses Basic auth (user:app_password) — required for Cloud ' +
                          'APP PASSWORDS. Leave BLANK for a Cloud/Server ACCESS TOKEN or Server PAT ' +
                          '(Bearer auth). See docs/ci-integrations.md § Atlassian auth schemes.'
        )

        // ── Pipeline-of-Pipelines chaining ─────────────────────────────────────
        string(name: 'UPSTREAM_JOB',   defaultValue: '', description: 'Name of the upstream pipeline that triggered this build (for chaining)')
        string(name: 'UPSTREAM_BUILD', defaultValue: '', description: 'Build number of the upstream job')
        string(name: 'DOWNSTREAM_JOB', defaultValue: '', description: 'Pipeline job to trigger on success (leave empty to disable)')
    }

    environment {
        // Persistent Rust toolchain cache — stored in the agent user's home directory so
        // it survives cleanWs() across builds.  Works for both Docker and native Jenkins:
        //   Docker  (jenkins/jenkins:lts):  HOME=/var/jenkins_home
        //   Native  (systemd / bare-metal): HOME=/var/lib/jenkins  (or wherever jenkins lives)
        // One-time setup per agent:
        //   Docker : rebuild ci/jenkins/Dockerfile.agent (toolchain baked at /opt/rust-toolchain)
        //   Native : sudo bash ci/jenkins/install-system-deps.sh
        //            bash ci/jenkins/install-rust-cache.sh
        CARGO_HOME  = "${env.HOME}/.rust-cache/cargo"
        RUSTUP_HOME = "${env.HOME}/.rust-cache/rustup"
        PATH        = "${env.HOME}/.rust-cache/cargo/bin:/usr/local/bin:/usr/bin:/bin"
        // WORKSPACE is set when the agent is acquired, before any stage runs — safe to reference here.
        BINARY        = "${WORKSPACE}/target/release/oxide-sloc"
        // ARTIFACT_PATH exposes the binary location to downstream chained jobs.
        ARTIFACT_PATH = "${WORKSPACE}/target/release/oxide-sloc"
        RUST_LOG      = 'warn'
    }

    stages {

        // ── 0. Checkout ────────────────────────────────────────────────────────
        // Always check out the tooling repo (REPO_URL) at the workspace root — the
        // scanner is built from it. When TARGET_REPO_URL is set, also check the
        // project-under-analysis out into ./_target and point SCAN_ROOT at it, so a
        // single job can scan any project. SCAN_ROOT is consumed by the analyze,
        // git-ref, and compare stages; it defaults to the workspace root (self-scan).
        stage('Checkout') {
            steps {
                script {
                    // Capture the tooling checkout's commit explicitly. With
                    // skipDefaultCheckout(true) + a scripted checkout, relying on the
                    // git plugin's implicit env.GIT_COMMIT is fragile (it reflects
                    // whichever checkout ran last). runBitbucketNotify() needs a real
                    // SHA or it treats itself as "not configured" and skips — so we
                    // set env.GIT_COMMIT here from the checkout return value.
                    def scmVars = checkout([$class: 'GitSCM',
                                            branches: [[name: '*/main']],
                                            userRemoteConfigs: [[url: params.REPO_URL]]])
                    env.GIT_COMMIT = scmVars.GIT_COMMIT ?: env.GIT_COMMIT
                }
                script {
                    if (params.TARGET_REF?.trim() &&
                            !(params.TARGET_REF.trim() ==~ /^[A-Za-z0-9_\-\.\/]+$/)) {
                        error("TARGET_REF contains invalid characters: ${params.TARGET_REF}")
                    }
                    if (params.TARGET_CREDENTIALS_ID?.trim() &&
                            !(params.TARGET_CREDENTIALS_ID.trim() ==~ /^[A-Za-z0-9_\-\.]+$/)) {
                        error("TARGET_CREDENTIALS_ID contains invalid characters: ${params.TARGET_CREDENTIALS_ID}")
                    }
                    if (params.TARGET_REPO_URL?.trim()) {
                        def ref = params.TARGET_REF?.trim() ?: 'main'
                        // Accept a bare branch/tag (map to origin) or an explicit ref/SHA.
                        def branchSpec = (ref ==~ /^[0-9a-fA-F]{7,40}$/ || ref.contains('/')) ? ref : "*/${ref}"
                        // Attach the credential only when provided, so public repos
                        // (and agents with ambient git auth) keep working unchanged.
                        def remoteCfg = [url: params.TARGET_REPO_URL.trim()]
                        if (params.TARGET_CREDENTIALS_ID?.trim()) {
                            remoteCfg['credentialsId'] = params.TARGET_CREDENTIALS_ID.trim()
                        }
                        dir('_target') {
                            def tgtVars = checkout([$class: 'GitSCM',
                                                    branches: [[name: branchSpec]],
                                                    userRemoteConfigs: [remoteCfg]])
                            // When scanning an external project, the Bitbucket
                            // build-status must attach to the SCANNED commit (the one
                            // being analyzed), not the tooling repo's HEAD — mirror the
                            // SLOC_PROJECT short-SHA logic, which also uses the target.
                            if (tgtVars?.GIT_COMMIT?.trim()) {
                                env.GIT_COMMIT = tgtVars.GIT_COMMIT
                            }
                        }
                        env.SCAN_ROOT = "${env.WORKSPACE}/_target"
                        def credNote = params.TARGET_CREDENTIALS_ID?.trim() ? " (creds: ${params.TARGET_CREDENTIALS_ID.trim()})" : ''
                        echo "Scanning external project at ${env.SCAN_ROOT} (ref: ${ref})${credNote}"
                    } else {
                        env.SCAN_ROOT = env.WORKSPACE
                    }
                }
            }
        }

        // ── 0b. Load helpers ───────────────────────────────────────────────────
        // Loads ci/jenkins/pipeline-helpers.groovy as a separate compiled class so
        // its methods get their own 64 KB bytecode budget, keeping this script lean.
        stage('Load helpers') {
            steps {
                script {
                    h = load 'ci/jenkins/pipeline-helpers.groovy'
                }
            }
        }

        // ── 1. Setup ───────────────────────────────────────────────────────────
        // Installs the Rust toolchain (cached persistently across builds) and
        // decompresses the vendor archive so all cargo commands run fully offline.
        //
        // Toolchain resolution order (stops at first match):
        //   1. Toolchain already in RUSTUP_HOME persistent cache      → no network
        //   2. rust-toolchain-bundle.tar.xz in workspace              → air-gapped
        //   3. /opt/rust-toolchain baked into the agent image         → air-gapped
        //   4. rustup-init binary at ${RUSTUP_HOME}/../rustup-init    → semi-offline
        //   5. curl sh.rustup.rs                                       → requires internet
        stage('Setup') {
            steps {
                retry(2) { script { h.runSetup() } }
            }
        }

        // ── 2. Quality Gates ───────────────────────────────────────────────────
        // Format and Lint run in parallel; Unit tests follow.
        // All skipped when SKIP_QUALITY_GATES is checked for faster scan-only runs.
        stage('Quality Gates') {
            when { expression { !params.SKIP_QUALITY_GATES } }
            stages {
                stage('fmt + clippy (parallel)') {
                    parallel {
                        stage('Format') {
                            steps { sh 'cargo fmt --all -- --check' }
                        }
                        stage('Lint') {
                            steps {
                                // Guard against status-masking shell pipes in
                                // Jenkins Groovy / ci shell (dash makes `cmd | tail`
                                // report 0 even on failure). Fast; runs before clippy.
                                sh 'bash ci/lint-pipeline-shell.sh'
                                // Single clippy run emitting JSON: it feeds the
                                // warnings-ng "Warnings" trend view AND still enforces
                                // -D warnings (we re-raise the failure below, after
                                // recording, so any issues are visible in the view even
                                // on a failing build). Matches the repo's lint gate
                                // (.gitlab-ci.yml, Makefile, ci/lint.sh): plain
                                // -D warnings, no pedantic/nursery.
                                sh '''
                                    set +e
                                    cargo clippy --workspace --all-targets --all-features \
                                        --message-format=json \
                                        -- -D warnings \
                                           -A clippy::multiple_crate_versions \
                                        > clippy.json 2> clippy-stderr.txt
                                    echo $? > clippy-rc.txt
                                    cat clippy-stderr.txt   # human-readable diagnostics in the console
                                '''
                                script {
                                    // Publish to warnings-ng. Guarded with Throwable so a
                                    // controller WITHOUT the plugin (missing recordIssues /
                                    // cargo step) still passes instead of erroring out.
                                    try {
                                        recordIssues(
                                            enabledForFailure: true,
                                            tools: [cargo(pattern: 'clippy.json',
                                                          id: 'clippy',
                                                          name: 'Clippy')]
                                        )
                                    } catch (Throwable t) {
                                        echo "recordIssues skipped (warnings-ng not installed): ${t.message}"
                                    }
                                    // Preserve the -D warnings gate: fail if clippy did.
                                    def rc = readFile('clippy-rc.txt').trim()
                                    if (rc != '0') {
                                        error("clippy failed with -D warnings (exit ${rc}). " +
                                              "See the Warnings view or the console output above.")
                                    }
                                }
                            }
                        }
                    }
                }
                stage('Unit tests') {
                    environment {
                        RUST_BACKTRACE = '1'
                    }
                    steps {
                        script { h.runUnitTests() }
                    }
                }
            }
        }

        // ── 3. Build ───────────────────────────────────────────────────────────
        stage('Build') {
            steps {
                retry(2) { sh 'cargo build --release -p oxide-sloc' }
            }
        }

        // ── 4. Coverage ────────────────────────────────────────────────────────
        // Produces LCOV, Cobertura XML, and browsable HTML via cargo-llvm-cov.
        // Enabled by COVERAGE_STANDALONE; threshold enforced by COVERAGE_THRESHOLD.
        stage('Coverage') {
            when {
                allOf {
                    expression { params.COVERAGE_STANDALONE }
                    expression { !params.SKIP_QUALITY_GATES }
                }
            }
            steps {
                // Never let a coverage/test hiccup cascade and wipe the rest of the
                // published dashboard: mark the build UNSTABLE and the stage FAILURE,
                // but keep going so Analyze / Archive & Publish (reports, plots,
                // warnings, HTML) still run.
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    script { h.runCoverage() }
                }
            }
        }

        // ── 5. Analyze ─────────────────────────────────────────────────────────
        // Mirrors the web UI configuration flow end-to-end.
        stage('Analyze') {
            steps {
                script { h.runAnalyze() }
            }
        }

        // ── 6. Web UI health check ─────────────────────────────────────────────
        stage('Web UI health check') {
            when { expression { !params.SKIP_WEB_CHECK } }
            steps {
                sh 'bash ci/jenkins/run-web-check.sh'
            }
        }

        // ── 7. Deliver results ─────────────────────────────────────────────────
        // Optional webhook and/or email delivery via the `send` subcommand.
        stage('Deliver results') {
            when {
                expression {
                    params.WEBHOOK_URL?.trim() || params.EMAIL_RECIPIENTS?.trim()
                }
            }
            stages {
                stage('Send webhook') {
                    when { expression { params.WEBHOOK_URL?.trim() as Boolean } }
                    steps {
                        script {
                            try {
                                def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                                sh """
                                    '${env.BINARY}' send '${outDir}/result_${env.SLOC_PROJECT ?: 'project'}.json' \\
                                        --webhook-url '${params.WEBHOOK_URL}'
                                """
                            } catch (err) {
                                unstable("Send webhook failed (delivery error, scan artifacts preserved): ${err.message}")
                            }
                        }
                    }
                }
                stage('Send email') {
                    when { expression { params.EMAIL_RECIPIENTS?.trim() as Boolean } }
                    environment {
                        SLOC_SMTP_HOST = credentials('SLOC_SMTP_HOST')
                        SLOC_SMTP_USER = credentials('SLOC_SMTP_USER')
                        SLOC_SMTP_PASS = credentials('SLOC_SMTP_PASS')
                    }
                    steps {
                        script {
                            try {
                                def outDir  = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                                def recArgs = params.EMAIL_RECIPIENTS.tokenize(',')
                                    .collect { "--smtp-to '${it.trim()}'" }.join(' ')
                                sh """
                                    '${env.BINARY}' send '${outDir}/result_${env.SLOC_PROJECT ?: 'project'}.json' \\
                                        --smtp-from "\${SLOC_SMTP_USER}" \\
                                        ${recArgs}
                                """
                            } catch (err) {
                                unstable("Send email failed (delivery error, scan artifacts preserved): ${err.message}")
                            }
                        }
                    }
                }
            }
        }

        // ── 8. Archive & Publish ───────────────────────────────────────────────
        // Writes Plot-plugin trend CSVs, archives artifacts, publishes HTML reports.
        stage('Archive & Publish') {
            steps {
                script { h.runArchivePublish() }
            }
        }

        // ── 9. Push to Artifact Repository ────────────────────────────────────
        // Pushes scan artifacts to an external repository via ci/artifact-push.sh.
        stage('Push to Artifact Repository') {
            when {
                allOf {
                    expression { params.ARTIFACT_REPO_TYPE != 'none' }
                    expression { params.ARTIFACT_REPO_URL?.trim() as Boolean }
                }
            }
            steps {
                script { h.runPushArtifacts() }
            }
        }

        // ── 10. Git-Ref Scan ──────────────────────────────────────────────────
        stage('Git-Ref Scan') {
            when {
                expression { return params.GIT_REF?.trim() != '' }
            }
            steps {
                withEnv([
                    "GIT_REF=${params.GIT_REF}",
                    "OUTPUT_SUBDIR=${params.OUTPUT_SUBDIR}",
                    "SCAN_ROOT=${env.SCAN_ROOT ?: env.WORKSPACE}",
                ]) {
                    sh 'bash ci/jenkins/run-git-ref-scan.sh'
                }
            }
        }

        // ── 11. Git-Ref Compare ────────────────────────────────────────────────
        // Compare two refs using oxide-sloc diff.
        stage('Git-Ref Compare') {
            when {
                expression {
                    return params.COMPARE_TO_REF?.trim() != '' || params.COMPARE_TO_PREV_TAG
                }
            }
            steps {
                script { h.runGitRefCompare() }
            }
        }

    } // end stages

    post {
        success {
            script {
                if (h != null) { h.runPostSuccess() }
            }
        }
        unstable {
            // A fresh agent without cargo-nextest produces an UNSTABLE build (the
            // Unit tests stage falls back to cargo test with no JUnit report). Run
            // the same summary so the build row gets its description/displayName
            // instead of showing blank; runPostSuccess skips the downstream trigger
            // on a non-SUCCESS result.
            script {
                if (h != null) { h.runPostSuccess() }
            }
        }
        failure {
            echo 'Build failed — review the stage output above for details.'
        }
        always {
            script {
                if (h != null) { h.runBitbucketNotify() }
            }
        }
        cleanup {
            // cleanup runs LAST — after success/failure/always — guaranteeing that
            // post { success } can still read result.json before the workspace is wiped.
            script {
                try {
                    cleanWs()
                } catch (Exception ex) {
                    echo "cleanWs skipped: ${ex.message}"
                }
            }
        }
    }
}
