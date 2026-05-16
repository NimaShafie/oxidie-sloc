/*
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
pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '5'))
        timestamps()
        timeout(time: 60, unit: 'MINUTES')
        ansiColor('xterm')
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

        // ── Source repository ──────────────────────────────────────────────────
        string(
            name:         'REPO_URL',
            defaultValue: 'https://github.com/oxide-sloc/oxide-sloc.git',
            description:  'Git repository URL to check out (branch: main). ' +
                          'Use file:///path/to/repo for air-gapped local repos.'
        )

        // ── Scan target ────────────────────────────────────────────────────────
        string(
            name:         'SCAN_PATH',
            defaultValue: 'tests/fixtures/basic',
            description:  'Directory (or space-separated paths) to scan — relative to the workspace root or absolute.'
        )
        string(
            name:         'REPORT_TITLE',
            defaultValue: 'oxide-sloc CI Report',
            description:  'Title embedded in generated HTML and PDF reports.'
        )
        string(
            name:         'OUTPUT_SUBDIR',
            defaultValue: 'ci-out',
            description:  'Output sub-directory for generated artifacts (relative to the workspace root). ' +
                          'The directory is created automatically if it does not exist. ' +
                          'All artifacts — result.json, report.html, report.csv, report.xlsx, report.pdf, and trend CSVs — ' +
                          'are written here and then archived to Jenkins at the end of each build. ' +
                          'Only safe path characters are allowed (letters, digits, hyphens, underscores, slashes).'
        )

        // ── Pipeline switches ──────────────────────────────────────────────────
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
            defaultValue: false,
            description:  'Write a PDF report artifact. ' +
                          'Requires a Chromium-based browser (Chrome, Edge, Brave, Vivaldi, or Opera) ' +
                          'installed on the agent. Set the SLOC_BROWSER environment variable to ' +
                          'specify a custom browser path, or SLOC_BROWSER_NOSANDBOX=1 for Docker.'
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
                          'Example: rust,python,javascript   (empty = all 41 supported languages)'
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
            description: 'Test runner for the Unit tests stage.\n' +
                         '  cargo-test    — standard stable cargo test; console output only (no JUnit XML)\n' +
                         '  cargo-nextest — faster parallel runner with JUnit XML output;\n' +
                         '                  requires cargo-nextest on the agent:\n' +
                         '                    cargo install cargo-nextest\n' +
                         '                  Enables the "Test Result" trend when PUBLISH_TEST_RESULTS is checked.'
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
                          'The HTML report is published as a "Coverage Report" sidebar link. ' +
                          'Requires cargo-llvm-cov (preferred) or cargo-tarpaulin on the agent:\n' +
                          '  cargo install cargo-llvm-cov && rustup component add llvm-tools-preview\n' +
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
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM',
                          branches: [[name: '*/main']],
                          userRemoteConfigs: [[url: params.REPO_URL]]])
            }
        }

        // ── 1. Setup ───────────────────────────────────────────────────────────
        // Installs the Rust toolchain (cached persistently across builds) and
        // decompresses the vendor archive so all cargo commands run fully offline.
        //
        // Toolchain resolution order (stops at first match):
        //   1. Toolchain already in RUSTUP_HOME persistent cache      → no network
        //   2. rust-toolchain-bundle.tar.xz in workspace              → air-gapped
        //      (run ci/jenkins/bundle-rust-toolchain.sh once, commit both output files)
        //   3. /opt/rust-toolchain baked into the agent image         → air-gapped
        //      (rebuild ci/jenkins/Dockerfile.agent; toolchain installed at build time)
        //   4. rustup-init binary at ${RUSTUP_HOME}/../rustup-init    → semi-offline
        //   5. curl sh.rustup.rs                                       → requires internet
        //
        // Preferred air-gapped paths: #2 (bundle committed to repo) or #3 (Dockerfile).
        // Cargo crate sources are always served from vendor.tar.xz — no crates.io needed.
        stage('Setup') {
            steps {
                sh '''
                    TOOLCHAIN=$(grep '^channel' rust-toolchain.toml | cut -d'"' -f2)
                    if rustup toolchain list 2>/dev/null | grep -q "${TOOLCHAIN}"; then
                        echo "Rust ${TOOLCHAIN} already in persistent cache — skipping install."
                    elif [ -f rust-toolchain-bundle.tar.xz ]; then
                        echo "Extracting rust-toolchain-bundle.tar.xz (air-gapped workspace bundle)..."
                        sha256sum -c rust-toolchain-bundle.tar.xz.sha256
                        tar -xJf rust-toolchain-bundle.tar.xz -C "${CARGO_HOME}/.."
                    elif [ -d /opt/rust-toolchain/rustup/toolchains ]; then
                        echo "Seeding toolchain from agent image (/opt/rust-toolchain)..."
                        cp -a /opt/rust-toolchain/cargo/. "${CARGO_HOME}/"
                        cp -a /opt/rust-toolchain/rustup/. "${RUSTUP_HOME}/"
                    elif [ -x "${RUSTUP_HOME}/../rustup-init" ]; then
                        echo "Using bundled rustup-init (semi-offline)..."
                        "${RUSTUP_HOME}/../rustup-init" -y \
                            --default-toolchain "${TOOLCHAIN}" \
                            --no-modify-path
                    else
                        echo "============================================================"
                        echo "WARNING: This build is NOT air-gapped."
                        echo "  Neither /opt/rust-toolchain (Dockerfile.agent layout) nor"
                        echo "  the pre-seeded rustup-init binary was found on this agent."
                        echo "  Falling back to internet rustup. To make this air-gap-safe,"
                        echo "  rebuild the agent image: see docs/ci-integrations.md"
                        echo "  § Rebuilding the agent image."
                        echo "============================================================"
                        echo "Downloading rustup installer (requires internet access)..."
                        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
                            | sh -s -- -y --default-toolchain "${TOOLCHAIN}" --no-modify-path
                    fi
                    rustup show
                    cargo --version
                '''
                sh '''
                    # vendor.tar.xz is committed to git and will always be present after
                    # checkout.  The agent-cache fallback handles the rare case where an
                    # older clone or a manually reset workspace is used instead.
                    AGENT_ARCHIVE="${CARGO_HOME}/../vendor.tar.xz"
                    AGENT_SHA="${CARGO_HOME}/../vendor.tar.xz.sha256"

                    # Stale vendor/ from a recycled workspace (cleanWs only runs in
                    # post{}; a prior session may have crashed before cleanup).  If
                    # vendor.tar.xz is alongside it, the tarball is authoritative —
                    # re-extract to guarantee Cargo.lock-aligned versions.
                    if [ -d vendor ] && [ -f vendor.tar.xz ]; then
                        echo "vendor/ exists alongside a tarball — wiping and re-extracting for freshness."
                        rm -rf vendor
                    fi
                    if [ -d vendor ]; then
                        echo "vendor/ already present — skipping extraction."
                    elif [ -f vendor.tar.xz ]; then
                        echo "Verifying vendor.tar.xz integrity..."
                        sha256sum -c vendor.tar.xz.sha256
                        echo "Decompressing vendor.tar.xz..."
                        tar -xJf vendor.tar.xz
                    elif [ -f "${AGENT_ARCHIVE}" ]; then
                        echo "vendor.tar.xz not in workspace — falling back to agent cache..."
                        cp "${AGENT_ARCHIVE}" vendor.tar.xz
                        if [ -f "${AGENT_SHA}" ]; then
                            cp "${AGENT_SHA}" vendor.tar.xz.sha256
                            echo "Verifying vendor.tar.xz integrity..."
                            sha256sum -c vendor.tar.xz.sha256
                        else
                            echo "WARNING: No .sha256 in agent cache — skipping checksum verification."
                        fi
                        echo "Decompressing vendor.tar.xz..."
                        tar -xJf vendor.tar.xz
                    else
                        echo "ERROR: vendor.tar.xz not found in workspace or agent cache." >&2
                        echo "       Ensure the repository was cloned from the correct branch/tag." >&2
                        exit 1
                    fi

                    echo "Writing .cargo/config.toml for fully offline builds..."
                    mkdir -p .cargo
                    cat > .cargo/config.toml << 'CARGOEOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CARGOEOF
                '''
                // Relax artifact-viewer CSP so HTML report artifacts render with inline
                // styles and scripts.  Calls the Jenkins Script Console via the REST API
                // using credential 'jenkins-api-token' (Kind: Secret text, value: admin
                // API token).  If the credential is absent this step is a no-op and falls
                // back to the init.groovy.d approach: bash ci/jenkins/preflight.sh --install-csp
                script {
                    try {
                        withCredentials([string(credentialsId: 'jenkins-api-token',
                                                variable:      'JEN_API_TOK',
                                                optional:      true)]) {
                            if (env.JEN_API_TOK?.trim()) {
                                def base = (env.BUILD_URL ?: '').replaceAll('/job/.*', '').replaceAll('/+$', '')
                                if (base) {
                                    withEnv(["SLOC_JENKINS_BASE=${base}",
                                             'SLOC_CSP=default-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: blob:; script-src \'self\' \'unsafe-inline\'; font-src \'self\' data:;']) {
                                        sh '''
                                            CRUMB=$(curl -sS -u "admin:${JEN_API_TOK}" \
                                                "${SLOC_JENKINS_BASE}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,%22::%22,//crumb)" \
                                                2>/dev/null || echo "")
                                            FIELD="${CRUMB%%::*}"
                                            CRUMB_VAL="${CRUMB##*::}"
                                            GROOVY="System.setProperty(\"hudson.model.DirectoryBrowserSupport.CSP\",\"${SLOC_CSP}\")"
                                            curl -sS -u "admin:${JEN_API_TOK}" \
                                                -H "${FIELD}: ${CRUMB_VAL}" \
                                                --data-urlencode "script=${GROOVY}" \
                                                "${SLOC_JENKINS_BASE}/scriptText" >/dev/null 2>&1 || true
                                            echo "Artifact-viewer CSP relaxed for this session."
                                        '''
                                    }
                                }
                            } else {
                                echo 'jenkins-api-token credential not configured — HTML reports may render unstyled in the artifact viewer.'
                                echo 'To fix permanently: bash ci/jenkins/preflight.sh --install-csp'
                            }
                        }
                    } catch (Exception ex) {
                        echo "CSP setup (non-fatal): ${ex.message}"
                    }
                }
            }
        }

        // ── 2. Quality Gates ───────────────────────────────────────────────────
        // Format and Lint run in parallel; Unit tests follow.
        // All skipped when SKIP_QUALITY_GATES is checked for faster scan-only runs.
        //
        // TEST_RUNNER controls which test harness is used:
        //   cargo-test    — standard stable runner; console output only
        //   cargo-nextest — faster parallel runner; produces JUnit XML at
        //                   <OUTPUT_SUBDIR>/test-results/junit.xml for the
        //                   Jenkins "Test Result" sidebar link (requires
        //                   PUBLISH_TEST_RESULTS + cargo-nextest on the agent).
        //
        // TEST_FAIL_FAST — stop on first failure (default: run all)
        // RUST_BACKTRACE=1 is always set so panics include full stack traces.
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
                                sh '''
                                    cargo clippy --workspace --all-targets --all-features \
                                        -- -D warnings \
                                           -W clippy::pedantic \
                                           -W clippy::nursery \
                                           -A clippy::multiple_crate_versions \
                                        2>&1 | tee clippy-output.txt
                                    WARN_COUNT=$(grep -c '^warning' clippy-output.txt 2>/dev/null || echo 0)
                                    echo "Clippy warnings captured: ${WARN_COUNT}"
                                '''
                            }
                        }
                    }
                }
                stage('Unit tests') {
                    environment {
                        // Full backtraces on panics — essential for diagnosing test failures.
                        RUST_BACKTRACE = '1'
                    }
                    steps {
                        script {
                            def outDir     = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                            def resultsDir = "${outDir}/test-results"
                            sh "mkdir -p '${resultsDir}'"

                            if (params.TEST_RUNNER == 'cargo-nextest') {
                                // cargo-nextest: parallel runner with JUnit XML output.
                                // JUnit XML is written by the CI profile defined in
                                // .config/nextest.toml (junit.path = "junit.xml").
                                // The file lands at the workspace root; we move it into
                                // the output directory so archiveArtifacts picks it up.
                                sh """
                                    if ! cargo nextest --version >/dev/null 2>&1; then
                                        echo "ERROR: cargo-nextest not found on this agent."
                                        echo "  Install: cargo install cargo-nextest"
                                        echo "  Or set TEST_RUNNER to 'cargo-test'."
                                        exit 1
                                    fi
                                """
                                def failFastFlag = params.TEST_FAIL_FAST ? '--fail-fast' : '--no-fail-fast'
                                sh """
                                    cargo nextest run --workspace ${failFastFlag} --profile ci \
                                        2>&1 | tee '${resultsDir}/nextest-output.txt'
                                """
                                // Move JUnit XML written by .config/nextest.toml CI profile
                                sh "mv -f junit.xml '${resultsDir}/junit.xml' 2>/dev/null || true"

                                if (params.PUBLISH_TEST_RESULTS) {
                                    junit testResults:         "${params.OUTPUT_SUBDIR}/test-results/junit.xml",
                                          allowEmptyResults:   true,
                                          skipPublishingChecks: false
                                }
                            } else {
                                // cargo test (stable default) — no JUnit XML, console output only.
                                def failFastFlag = params.TEST_FAIL_FAST ? '' : '--no-fail-fast'
                                sh """
                                    cargo test --workspace ${failFastFlag}
                                """
                            }
                        }
                    }
                }
            }
        }

        // ── 3. Build ───────────────────────────────────────────────────────────
        stage('Build') {
            steps {
                // retry once on transient network or registry errors
                retry(2) { sh 'cargo build --release -p oxide-sloc' }
            }
        }

        // ── 3a. Coverage ──────────────────────────────────────────────────────
        // Standalone code-coverage stage.  Enabled by COVERAGE_STANDALONE.  Produces:
        //
        //   <OUTPUT_SUBDIR>/coverage/lcov.info          — LCOV (line + branch coverage)
        //   <OUTPUT_SUBDIR>/coverage/cobertura.xml      — Cobertura XML
        //   <OUTPUT_SUBDIR>/coverage/html/index.html    — browsable HTML source view
        //
        // Jenkins integration via the Coverage plugin (recordCoverage step):
        //   • Line %, branch %, function % shown on every build page
        //   • Build-over-build coverage trend chart (no Plot CSV needed)
        //   • Per-file drill-down from the Jenkins UI
        //   • Quality-gate enforcement via COVERAGE_THRESHOLD (no shell math needed)
        //   Install: see ci/jenkins/plugins.txt — plugin ID: coverage
        //
        // Prerequisites:
        //   cargo-llvm-cov (preferred, vendored in ci/tools/Cargo.toml) — produces
        //     LCOV with line + branch data and an HTML source report.
        //   cargo-tarpaulin — fallback; produces LCOV (line coverage only).
        //   genhtml (lcov system package) — fallback HTML when cargo-llvm-cov absent.
        //   llvm-tools rustup component — required by cargo-llvm-cov (in rust-toolchain.toml).
        stage('Coverage') {
            when {
                allOf {
                    expression { params.COVERAGE_STANDALONE }
                    expression { !params.SKIP_QUALITY_GATES }
                }
            }
            steps {
                script {
                    def outDir      = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                    def coverageDir = "${outDir}/coverage"
                    sh "mkdir -p '${coverageDir}'"

                    // ── 1. Ensure cargo-llvm-cov is available ─────────────────
                    // Installs from the vendored source tree (no internet needed).
                    // llvm-tools component is declared in rust-toolchain.toml and
                    // will already be present in any toolchain bundle built from it.
                    sh '''
                        if ! cargo llvm-cov --version >/dev/null 2>&1; then
                            echo "Installing cargo-llvm-cov from vendor (offline)..."
                            cargo install --offline cargo-llvm-cov || \
                                echo "WARNING: cargo-llvm-cov unavailable; tarpaulin fallback will be used."
                        fi
                        rustup component add llvm-tools 2>/dev/null || true
                    '''

                    // ── 2. Generate LCOV + Cobertura XML ─────────────────────
                    // ci/sonar/generate-coverage.sh tries cargo-llvm-cov first
                    // (LCOV includes branch data: BRH/BRF lines), then falls back
                    // to cargo-tarpaulin (line coverage only, no branch data).
                    sh "bash ci/sonar/generate-coverage.sh '${coverageDir}'"

                    // ── 3. Generate browsable HTML source report ──────────────
                    // Priority:
                    //   a) cargo-llvm-cov --html  — annotated source view with
                    //      line + branch hit/miss highlighting
                    //   b) genhtml (lcov package)  — standard LCOV HTML; works
                    //      even when cargo-llvm-cov is absent (tarpaulin case)
                    sh """
                        if cargo llvm-cov --version >/dev/null 2>&1; then
                            echo "==> Generating HTML report with cargo-llvm-cov"
                            cargo llvm-cov --workspace --all-features \
                                --html --output-dir '${coverageDir}/html'
                        elif command -v genhtml >/dev/null 2>&1; then
                            echo "==> Generating HTML report with genhtml (lcov fallback)"
                            genhtml '${coverageDir}/lcov.info' \
                                --output-directory '${coverageDir}/html' \
                                --legend \
                                --branch-coverage \
                                --title 'oxide-sloc coverage' \
                                2>&1 | tail -20
                        else
                            echo "HTML coverage report: skipped (install cargo-llvm-cov or lcov package)."
                        fi
                    """

                    // ── 4. Feed LCOV + Cobertura into the Jenkins Coverage plugin
                    // recordCoverage provides native Jenkins UI integration:
                    //   • Coverage summary badge on the build page
                    //   • Line / branch / function percentages
                    //   • Per-file source drill-down
                    //   • Build-over-build trend chart (built into the plugin)
                    //   • Quality-gate enforcement (COVERAGE_THRESHOLD)
                    //
                    // Both parsers are registered; Jenkins shows the union of what
                    // each file finds — LCOV is the primary source (it carries branch
                    // data), Cobertura provides the function-level metric.
                    //
                    // Requires the "coverage" plugin — see ci/jenkins/plugins.txt.
                    script {
                        def threshold = params.COVERAGE_THRESHOLD?.trim()?.isDouble()
                                            ? params.COVERAGE_THRESHOLD.trim().toDouble()
                                            : (params.COVERAGE_THRESHOLD?.trim()?.isInteger()
                                                ? params.COVERAGE_THRESHOLD.trim().toInteger() as Double
                                                : 0.0)

                        def lcovFile     = "${params.OUTPUT_SUBDIR}/coverage/lcov.info"
                        def coberturaFile = "${params.OUTPUT_SUBDIR}/coverage/sonar-coverage.xml"

                        def tools = []
                        if (fileExists("${env.WORKSPACE}/${lcovFile}")) {
                            tools << [parser: 'LCOV', pattern: lcovFile]
                        }
                        if (fileExists("${env.WORKSPACE}/${coberturaFile}")) {
                            tools << [parser: 'COBERTURA', pattern: coberturaFile]
                        }

                        if (tools.isEmpty()) {
                            echo 'WARNING: No coverage data files found — recordCoverage skipped.'
                        } else {
                            // Quality gates: line coverage threshold is user-configured;
                            // branch coverage is advisory (UNSTABLE, not FAILURE) because
                            // tarpaulin may not emit branch data.
                            def gates = []
                            if (threshold > 0) {
                                gates << [threshold: threshold, metric: 'LINE',
                                          baseline: 'PROJECT', criticality: 'FAILURE']
                                gates << [threshold: threshold * 0.7, metric: 'BRANCH',
                                          baseline: 'PROJECT', criticality: 'UNSTABLE']
                            }

                            recordCoverage(
                                tools:               tools,
                                id:                  'oxide-sloc-coverage',
                                name:                'Coverage',
                                // Keep source snapshots on every build so drill-down
                                // works on historical builds, not just the latest.
                                sourceCodeRetention: 'EVERY_BUILD',
                                qualityGates:        gates
                            )
                        }
                    }

                    // ── 5. Publish HTML source report as a sidebar link ───────
                    // The Coverage plugin provides its own trend view; this sidebar
                    // link gives direct access to the annotated source HTML produced
                    // by cargo-llvm-cov or genhtml.
                    if (fileExists("${coverageDir}/html/index.html")) {
                        publishHTML(target: [
                            allowMissing         : false,
                            alwaysLinkToLastBuild: true,
                            keepAll              : true,
                            reportDir            : "${params.OUTPUT_SUBDIR}/coverage/html",
                            reportFiles          : 'index.html',
                            reportName           : 'Coverage Source',
                        ])
                    } else {
                        echo 'Annotated HTML source report not available for this run.'
                    }
                }
            }
        }

        // ── 4. Analyze ─────────────────────────────────────────────────────────
        // Mirrors the web UI configuration flow end-to-end:
        //   Step 1 → target path       (SCAN_PATH)
        //   Step 2 → counting rules    (CI_PRESET, MIXED_LINE_POLICY, DOCSTRINGS_AS_CODE, …)
        //   Step 3 → output artifacts  (GENERATE_HTML / PDF; JSON + CSV + XLSX always written)
        //   Step 4 → run + validate
        //   Step 5 → mixed-line policy matrix (spot-checks all four policies)
        stage('Analyze') {
            steps {
                script {
                    // CSP is set via ci/jenkins/init.groovy.d/relax-csp.groovy (drop into $JENKINS_HOME/init.groovy.d/)

                    // Allowlist-check choice and free-text parameters before use.
                    // Free-text values are passed to the shell via withEnv (environment
                    // variables), not Groovy string interpolation.
                    def allowedPolicies = ['code-only', 'code-and-comment', 'comment-only', 'separate-mixed-category']
                    def allowedPresets  = ['none', 'default', 'strict', 'full-scope']
                    if (!allowedPolicies.contains(params.MIXED_LINE_POLICY)) {
                        error("Invalid MIXED_LINE_POLICY value: ${params.MIXED_LINE_POLICY}")
                    }
                    if (!allowedPresets.contains(params.CI_PRESET)) {
                        error("Invalid CI_PRESET value: ${params.CI_PRESET}")
                    }
                    if (params.OUTPUT_SUBDIR && !(params.OUTPUT_SUBDIR ==~ /^[a-zA-Z0-9_\-\/]+$/)) {
                        error("OUTPUT_SUBDIR contains invalid characters: ${params.OUTPUT_SUBDIR}")
                    }
                    def safeGlob = /^[a-zA-Z0-9_\-\.\*\?\[\]\/\\]+$/
                    if (params.INCLUDE_GLOBS) {
                        params.INCLUDE_GLOBS.tokenize(',').each { g ->
                            if (!(g.trim() ==~ safeGlob)) { error("INCLUDE_GLOBS contains invalid pattern: ${g.trim()}") }
                        }
                    }
                    if (params.EXCLUDE_GLOBS) {
                        params.EXCLUDE_GLOBS.tokenize(',').each { g ->
                            if (!(g.trim() ==~ safeGlob)) { error("EXCLUDE_GLOBS contains invalid pattern: ${g.trim()}") }
                        }
                    }
                    // Language names: alphanumeric plus # and + (for C# and C++).
                    if (params.ENABLED_LANGUAGES) {
                        params.ENABLED_LANGUAGES.tokenize(',').each { l ->
                            if (!(l.trim() ==~ /^[a-zA-Z0-9\+\#]+$/)) {
                                error("ENABLED_LANGUAGES contains invalid value: ${l.trim()}")
                            }
                        }
                    }

                    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                    sh "mkdir -p '${outDir}'"

                    // Derive a URL-safe slug from the scan-path basename for named artifacts.
                    // e.g. "tests/fixtures/basic" → "basic", "src/my repo" → "my-repo"
                    def scanParts   = params.SCAN_PATH.trim().split('[/\\\\]') as List
                    def projectSlug = (scanParts ? scanParts[-1] : params.SCAN_PATH.trim())
                                        .replaceAll(/[^a-zA-Z0-9_\-]/, '-')
                                        .replaceAll(/-+/, '-')
                                        .replaceAll(/^-|-$/, '') ?: 'project'
                    env.SLOC_PROJECT = projectSlug

                    def configArg   = (params.CI_PRESET != 'none')
                                        ? "--config 'ci/sloc-ci-${params.CI_PRESET}.toml'"
                                        : ''
                    // JSON, CSV, and XLSX are always written.
                    // HTML and PDF are optional (controlled by GENERATE_HTML / GENERATE_PDF).
                    def jsonArg     = "--json-out  '${outDir}/result_${projectSlug}.json'"
                    def csvArg      = "--csv-out   '${outDir}/report_${projectSlug}.csv'"
                    def xlsxArg     = "--xlsx-out  '${outDir}/report_${projectSlug}.xlsx'"
                    def htmlArg     = params.GENERATE_HTML       ? "--html-out '${outDir}/report_${projectSlug}.html'" : ''
                    def pdfArg      = params.GENERATE_PDF        ? "--pdf-out  '${outDir}/report_${projectSlug}.pdf'"  : ''
                    def docArg      = params.DOCSTRINGS_AS_CODE  ? '--python-docstrings-as-code'        : ''
                    def symlinkArg  = params.FOLLOW_SYMLINKS     ? '--follow-symlinks'                  : ''
                    def noIgnoreArg = params.NO_IGNORE_FILES     ? '--no-ignore-files'                  : ''
                    def submodArg   = params.SUBMODULE_BREAKDOWN ? '--submodule-breakdown'              : ''

                    def includeArgs = params.INCLUDE_GLOBS
                        ? params.INCLUDE_GLOBS.tokenize(',').collect { "--include-glob '${it.trim()}'" }.join(' ')
                        : ''
                    def excludeArgs = params.EXCLUDE_GLOBS
                        ? params.EXCLUDE_GLOBS.tokenize(',').collect { "--exclude-glob '${it.trim()}'" }.join(' ')
                        : ''
                    def langArgs    = params.ENABLED_LANGUAGES
                        ? params.ENABLED_LANGUAGES.tokenize(',').collect { "--enabled-language '${it.trim()}'" }.join(' ')
                        : ''

                    // a. Quick plain summary
                    withEnv(["SCAN_PATH=${params.SCAN_PATH}"]) {
                        sh '''
                            "${BINARY}" analyze "${SCAN_PATH}" --plain ''' + configArg + '''
                        '''
                    }

                    // b. Main artifact run — JSON, CSV, XLSX always written; HTML and PDF are optional.
                    withEnv([
                        "SCAN_PATH=${params.SCAN_PATH}",
                        "REPORT_TITLE=${params.REPORT_TITLE}",
                        "MIXED_LINE_POLICY=${params.MIXED_LINE_POLICY}",
                    ]) {
                        sh '''
                            "${BINARY}" analyze "${SCAN_PATH}" \
                                --report-title "${REPORT_TITLE}" \
                                --mixed-line-policy "${MIXED_LINE_POLICY}" \
                                ''' + "${configArg} ${docArg} ${symlinkArg} ${noIgnoreArg} ${submodArg}" + ''' \
                                ''' + "${langArgs} ${includeArgs} ${excludeArgs}" + ''' \
                                ''' + "${jsonArg} ${csvArg} ${xlsxArg} ${htmlArg} ${pdfArg}" + '''
                        '''
                    }

                    sh "test -s '${outDir}/result_${projectSlug}.json'"
                    sh "test -s '${outDir}/report_${projectSlug}.csv'"
                    sh "test -s '${outDir}/report_${projectSlug}.xlsx'"
                    if (params.GENERATE_HTML) { sh "test -s '${outDir}/report_${projectSlug}.html'" }

                    // c. Per-file breakdown
                    withEnv(["SCAN_PATH=${params.SCAN_PATH}"]) {
                        sh '''
                            "${BINARY}" analyze "${SCAN_PATH}" --per-file --plain ''' + configArg + '''
                        '''
                    }

                    // d. HTML content sanity checks
                    if (params.GENERATE_HTML) {
                        withEnv(["REPORT_TITLE=${params.REPORT_TITLE}"]) {
                            sh '''
                                grep -q 'OxideSLOC' "''' + outDir + '''/report_''' + projectSlug + '''.html"
                                grep -qF "${REPORT_TITLE}" "''' + outDir + '''/report_''' + projectSlug + '''.html"
                            '''
                        }
                    }

                    // f. Mixed-line policy matrix — spot-checks all four policies
                    for (def policy in ['code-only', 'code-and-comment', 'comment-only', 'separate-mixed-category']) {
                        withEnv(["SCAN_PATH=${params.SCAN_PATH}"]) {
                            sh '''
                                "${BINARY}" analyze "${SCAN_PATH}" --plain --mixed-line-policy ''' + policy + '''
                            '''
                        }
                    }
                }
            }
        }

        // ── 6. Web UI health check ─────────────────────────────────────────────
        stage('Web UI health check') {
            when { expression { !params.SKIP_WEB_CHECK } }
            steps {
                sh '''
                    "${BINARY}" serve &
                    SERVER_PID=$!

                    HTTP_CODE="000"
                    for _ in $(seq 1 30); do
                        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:4317/ 2>/dev/null || echo "000")
                        [ "${HTTP_CODE}" = "200" ] && break
                        sleep 1
                    done

                    kill "${SERVER_PID}" 2>/dev/null || true
                    wait "${SERVER_PID}" 2>/dev/null || true

                    if [ "${HTTP_CODE}" != "200" ]; then
                        echo "Web UI returned HTTP ${HTTP_CODE} — expected 200"
                        exit 1
                    fi
                    echo "Web UI responded with HTTP 200 — OK"
                '''
            }
        }

        // ── 6. Deliver results ─────────────────────────────────────────────────
        // Optional webhook and/or email delivery via the `send` subcommand.
        //
        // Webhook:  set WEBHOOK_URL parameter; add SLOC_WEBHOOK_TOKEN (Secret Text)
        //           credential in Jenkins for Bearer-token auth (optional).
        // Email:    set EMAIL_RECIPIENTS parameter; add three Secret Text credentials:
        //           SLOC_SMTP_HOST, SLOC_SMTP_USER, SLOC_SMTP_PASS.
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
                            def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                            sh """
                                '${env.BINARY}' send '${outDir}/result.json' \\
                                    --webhook-url '${params.WEBHOOK_URL}'
                            """
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
                            def outDir  = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                            def recArgs = params.EMAIL_RECIPIENTS.tokenize(',')
                                .collect { "--smtp-to '${it.trim()}'" }.join(' ')
                            sh """
                                '${env.BINARY}' send '${outDir}/result.json' \\
                                    --smtp-from "\${SLOC_SMTP_USER}" \\
                                    ${recArgs}
                            """
                        }
                    }
                }
            }
        }

        // ── 7. Archive & Publish ───────────────────────────────────────────────
        // Generates trend-chart CSV data for the Plot plugin, archives all build
        // artifacts (binary, reports, test-results, coverage), and publishes the
        // HTML report as a build sidebar link.
        //
        // Prerequisite plugins — see ci/jenkins/plugins.txt:
        //   htmlpublisher  → "SLOC Report" and "Coverage Report" sidebar links
        //   plot           → build-over-build trend charts on the job page
        //   junit          → "Test Result" sidebar link (cargo-nextest runs only)
        //
        // CSV files written here (consumed by post { always } plot() calls):
        //   summary.csv      — aggregate totals: code / comment / blank / files
        //   per_language.csv — per-language code-line counts
        //   coverage.csv     — line coverage % (when COVERAGE_STANDALONE is enabled)
        stage('Archive & Publish') {
            steps {
                script {
                    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"

                    // Write CSV trend data consumed by the Plot plugin.
                    def proj     = env.SLOC_PROJECT ?: 'project'
                    def jobSlug  = (env.JOB_NAME?.replaceAll('[^a-zA-Z0-9_\\-]', '_') ?: 'oxide-sloc')
                    def histFile = "${env.HOME}/.oxide-sloc-history/${jobSlug}.csv"
                    sh """python3 - <<'PYEOF'
import json, csv, os, sys, re, time

out = "${outDir}"

# ── SLOC summary CSV ─────────────────────────────────────────────────────
result_path = out + "/result_${proj}.json"
if os.path.exists(result_path):
    data   = json.load(open(result_path))
    totals = data["summary_totals"]

    # summary.csv — one aggregate row per build for trend line charts
    with open(out + "/summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["code_lines", "comment_lines", "blank_lines", "files_analyzed"])
        w.writerow([totals["code_lines"], totals["comment_lines"],
                    totals["blank_lines"], totals["files_analyzed"]])

    # per_language.csv — one row per language for the per-language bar chart
    langs = data.get("totals_by_language", [])
    with open(out + "/per_language.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["language", "code_lines"])
        for lang in langs:
            display = lang.get("language", {})
            name = display if isinstance(display, str) else str(display)
            w.writerow([name, lang["code_lines"]])

    print("SLOC trend CSVs written to:", out)
else:
    print("result.json not found — skipping SLOC CSV generation")

# ── Coverage CSV ─────────────────────────────────────────────────────────
lcov_path = out + "/coverage/lcov.info"
if os.path.exists(lcov_path):
    total = hit = 0
    for line in open(lcov_path):
        line = line.strip()
        if line.startswith("LF:"):
            total += int(line[3:])
        elif line.startswith("LH:"):
            hit += int(line[3:])
    pct = round(hit / total * 100, 1) if total > 0 else 0.0
    with open(out + "/coverage.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["line_coverage_pct"])
        w.writerow([pct])
    print(f"Coverage trend CSV: {pct}% line coverage ({hit}/{total} lines hit)")
else:
    print("lcov.info not found — skipping coverage CSV")

# ── Persistent trend history ─────────────────────────────────────────────
# Written to agent home (outside workspace) so it survives cleanWs().
# Read by generate-dashboard.py to render a build-over-build sparkline.
history_file = "${histFile}"
if history_file and os.path.exists(result_path):
    ts        = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    build_num = os.environ.get('BUILD_NUMBER', '0')
    hist_dir  = os.path.dirname(history_file)
    if hist_dir:
        os.makedirs(hist_dir, exist_ok=True)
    header = 'timestamp,build,code_lines,comment_lines,blank_lines,files_analyzed\\n'
    if not os.path.exists(history_file):
        open(history_file, 'w').write(header)
    with open(history_file, 'a') as hf:
        hf.write(f"{ts},{build_num},{totals['code_lines']},"
                 f"{totals['comment_lines']},{totals['blank_lines']},"
                 f"{totals['files_analyzed']}\\n")
    with open(history_file) as hf:
        lines = hf.readlines()
    if len(lines) > 51:
        with open(history_file, 'w') as hf:
            hf.write(lines[0])
            hf.writelines(lines[-50:])
    print(f"Trend history updated: {history_file} ({len(lines)} entries)")
PYEOF"""

                    // Archive binary + all output subdirectory contents.
                    // Includes: result.json, report.csv, report.xlsx, report.html, report.pdf,
                    // test-results/, coverage/, and trend CSVs.
                    archiveArtifacts artifacts: "${params.OUTPUT_SUBDIR}/**",
                        fingerprint: true,
                        allowEmptyArchive: true

                    // ── Graphical Report (published first → top of sidebar) ───
                    // generate-dashboard.py reads result_<slug>.json and produces
                    // a self-contained HTML page with SVG charts and tables.
                    // CSS is extracted to an external file so it renders correctly
                    // under Jenkins's default artifact-viewer CSP.
                    try {
                        sh "python3 ci/jenkins/generate-dashboard.py '${outDir}' '${proj}' '${histFile}'"
                        def dashFile = "${outDir}/dashboard_${proj}.html"
                        if (fileExists(dashFile)) {
                            publishHTML(target: [
                                allowMissing         : true,
                                alwaysLinkToLastBuild: true,
                                keepAll              : true,
                                reportDir            : params.OUTPUT_SUBDIR,
                                reportFiles          : "dashboard_${env.SLOC_PROJECT ?: 'project'}.html",
                                reportName           : "Graphical Report — ${env.SLOC_PROJECT ?: 'project'}",
                            ])
                        }
                    } catch (Exception ex) {
                        echo "generate-dashboard.py did not run (Python 3 unavailable or script error): ${ex.message}"
                    }

                    if (params.GENERATE_HTML) {
                        def rptName = "SLOC Report — ${env.SLOC_PROJECT ?: 'project'}"
                        publishHTML(target: [
                            allowMissing         : false,
                            alwaysLinkToLastBuild: true,
                            keepAll              : true,
                            reportDir            : params.OUTPUT_SUBDIR,
                            reportFiles          : "report_${env.SLOC_PROJECT ?: 'project'}.html",
                            reportName           : rptName,
                        ])
                    }
                }
            }
        }

        // ── 8. Push to artifact repository ────────────────────────────────────
        // Pushes scan artifacts (JSON, CSV, XLSX, HTML, PDF) to an external artifact repository.
        // Only runs when ARTIFACT_REPO_TYPE is not "none" and ARTIFACT_REPO_URL is set.
        //
        // The push is delegated to ci/artifact-push.sh which handles all provider
        // differences.  Credentials are bound via withCredentials using optional: true
        // so the stage does not fail when the credential IDs are not yet registered —
        // the script will simply perform an unauthenticated push (or fail with a 401
        // if the repository requires auth, which surfaces as a clear error).
        //
        // Jenkins credential IDs to pre-register (Kind: Secret Text):
        //   SLOC_ARTIFACT_REPO_USER  — username or access key ID
        //   SLOC_ARTIFACT_REPO_PASS  — password, API token, or secret key
        stage('Push to Artifact Repository') {
            when {
                allOf {
                    expression { params.ARTIFACT_REPO_TYPE != 'none' }
                    expression { params.ARTIFACT_REPO_URL?.trim() as Boolean }
                }
            }
            steps {
                script {
                    def allowedTypes = [
                        'artifactory', 'nexus', 'nexus2', 's3', 'minio', 'azure-blob', 'generic-http'
                    ]
                    if (!allowedTypes.contains(params.ARTIFACT_REPO_TYPE)) {
                        error("Invalid ARTIFACT_REPO_TYPE: ${params.ARTIFACT_REPO_TYPE}")
                    }

                    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"

                    // Substitute runtime tokens in the repo path
                    def repoPath = params.ARTIFACT_REPO_PATH
                        .replace('${JOB_NAME}',    env.JOB_NAME    ?: 'unknown-job')
                        .replace('${BUILD_NUMBER}', env.BUILD_NUMBER ?: '0')

                    def filesToPush = []
                    if (params.ARTIFACT_PUSH_JSON)                           filesToPush << 'result.json'
                    if (params.ARTIFACT_PUSH_CSV)                            filesToPush << 'report.csv'
                    if (params.ARTIFACT_PUSH_XLSX)                           filesToPush << 'report.xlsx'
                    if (params.ARTIFACT_PUSH_HTML && params.GENERATE_HTML)   filesToPush << 'report.html'
                    if (params.ARTIFACT_PUSH_PDF  && params.GENERATE_PDF)    filesToPush << 'report.pdf'

                    if (filesToPush.isEmpty()) {
                        echo 'No artifact files selected for push — skipping.'
                        return
                    }

                    // Bind credentials as optional so the stage does not abort when
                    // the credential IDs are absent (Credentials Binding plugin ≥ 1.27).
                    withCredentials([
                        string(credentialsId: 'SLOC_ARTIFACT_REPO_USER',
                               variable:      'SLOC_AR_USER',
                               optional:      true),
                        string(credentialsId: 'SLOC_ARTIFACT_REPO_PASS',
                               variable:      'SLOC_AR_PASS',
                               optional:      true),
                    ]) {
                        withEnv([
                            "ARTIFACT_REPO_TYPE=${params.ARTIFACT_REPO_TYPE}",
                            "ARTIFACT_REPO_URL=${params.ARTIFACT_REPO_URL}",
                            "ARTIFACT_REPO_PATH=${repoPath}",
                            "ARTIFACT_REPO_EXTRA=${params.ARTIFACT_REPO_EXTRA ?: ''}",
                            "ARTIFACT_DIR=${outDir}",
                            "ARTIFACT_FILES=${filesToPush.join(' ')}",
                            "ARTIFACT_REPO_USER=${env.SLOC_AR_USER ?: ''}",
                            "ARTIFACT_REPO_PASS=${env.SLOC_AR_PASS ?: ''}",
                        ]) {
                            sh 'bash ci/artifact-push.sh'
                        }
                    }
                }
            }
        }

        // ── Git-ref scan ──────────────────────────────────────────────────────
        // When GIT_REF is set, scan that specific commit/tag/branch in addition
        // to the standard scan.  A temporary git worktree is used so the main
        // workspace stays clean.
        stage('Git-Ref Scan') {
            when {
                expression { return params.GIT_REF?.trim() != '' }
            }
            steps {
                sh '''
                    REF="${GIT_REF:-}"
                    OUT="${WORKSPACE}/${OUTPUT_SUBDIR}"
                    WT="${WORKSPACE}/.wt-ref-scan"

                    echo "=== Git-Ref Scan: ${REF} ==="
                    git worktree add --detach "${WT}" "${REF}"

                    "${BINARY}" analyze "${WT}" \
                        --json-out  "${OUT}/ref-scan.json" \
                        --html-out  "${OUT}/ref-scan.html" \
                        --csv-out   "${OUT}/ref-scan-summary.csv" \
                        --report-title "Ref scan: ${REF}" \
                        --plain

                    git worktree remove --force "${WT}" || true
                '''
            }
        }

        // ── Git-ref comparison ─────────────────────────────────────────────────
        // Compare two refs using oxide-sloc diff.  The baseline is resolved from
        // COMPARE_TO_PREV_TAG (auto-detect), COMPARE_TO_REF, or skipped if empty.
        stage('Git-Ref Compare') {
            when {
                expression {
                    return params.COMPARE_TO_REF?.trim() != '' || params.COMPARE_TO_PREV_TAG
                }
            }
            steps {
                sh '''
                    OUT="${WORKSPACE}/${OUTPUT_SUBDIR}"
                    BINARY="${WORKSPACE}/target/release/oxide-sloc"

                    # Resolve baseline ref
                    if [ "${COMPARE_TO_PREV_TAG:-false}" = "true" ]; then
                        CURRENT_TAG=$(git tag --sort=-version:refname | head -1)
                        BASELINE_TAG=$(git tag --sort=-version:refname | grep -v "^${CURRENT_TAG}$" | head -1)
                        BASELINE_REF="${BASELINE_TAG}"
                        echo "Auto-detected previous tag: ${BASELINE_REF} (current: ${CURRENT_TAG})"
                    else
                        BASELINE_REF="${COMPARE_TO_REF}"
                    fi

                    if [ -z "${BASELINE_REF}" ]; then
                        echo "No baseline ref found — skipping comparison."
                        exit 0
                    fi

                    # Determine what was scanned as "current"
                    CURRENT_JSON="${OUT}/ref-scan.json"
                    if [ ! -f "${CURRENT_JSON}" ]; then
                        CURRENT_JSON="${OUT}/result.json"
                    fi
                    if [ ! -f "${CURRENT_JSON}" ]; then
                        echo "No current scan JSON found — cannot compare."
                        exit 1
                    fi

                    echo "=== Scanning baseline: ${BASELINE_REF} ==="
                    WT_BASE="${WORKSPACE}/.wt-baseline"
                    git worktree add --detach "${WT_BASE}" "${BASELINE_REF}"

                    "${BINARY}" analyze "${WT_BASE}" \
                        --json-out  "${OUT}/baseline-scan.json" \
                        --report-title "Baseline: ${BASELINE_REF}" \
                        --plain

                    git worktree remove --force "${WT_BASE}" || true

                    echo "=== Computing diff ==="
                    "${BINARY}" diff \
                        "${OUT}/baseline-scan.json" \
                        "${CURRENT_JSON}" \
                        --json-out "${OUT}/diff.json" \
                        --csv-out  "${OUT}/diff.csv" \
                        --plain
                '''
            }
        }

    } // end stages

    post {
        success {
            script {
                // Set build description and display name from JSON totals + optional
                // test-result and coverage stats.  Runs before cleanup so all output
                // files are still on disk.
                try {
                    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
                    def proj   = env.SLOC_PROJECT
                                    ?: (params.SCAN_PATH?.trim()?.split('[/\\\\]') as List)?.last()
                                    ?: 'project'
                    def result = readJSON file: "${outDir}/result_${proj}.json"
                    def t      = result.summary_totals

                    // Compact number formatter (matches CLAUDE.md canonical spec)
                    def fmtN = { n ->
                        long v = n as long
                        long a = Math.abs(v)
                        if (a >= 1_000_000L) {
                            String s = String.format('%.1f', v / 1_000_000.0) + 'M'
                            return s.replace('.0M', 'M')
                        }
                        if (a >= 10_000L) return "${Math.round(v / 1_000.0)}K"
                        return String.format('%,d', v)
                    }
                    // Build description uses plain text so it renders correctly under
                    // any Jenkins markup formatter (Escaped HTML is the default).
                    def desc = "${fmtN(t.code_lines)} code · " +
                               "${fmtN(t.comment_lines)} cmts · " +
                               "${fmtN(t.blank_lines)} blank · " +
                               "${fmtN(t.files_analyzed)} files | ${params.SCAN_PATH}"

                    // Append test-result stats (cargo-nextest JUnit XML)
                    def junitPath = "${outDir}/test-results/junit.xml"
                    if (fileExists(junitPath)) {
                        try {
                            def junit      = readFile(junitPath)
                            def tm = junit =~ /tests="(\d+)"/
                            def fm = junit =~ /failures="(\d+)"/
                            def em = junit =~ /errors="(\d+)"/
                            def totalTests = tm ? (tm[0][1] as long) : 0L
                            def failCount  = fm ? (fm[0][1] as long) : 0L
                            def errCount   = em ? (em[0][1] as long) : 0L
                            def passCount  = Math.max(0L, totalTests - failCount - errCount)
                            def testStatus = (failCount == 0 && errCount == 0) ? 'OK' : "FAIL(${fmtN(failCount)})"
                            desc += " · ${fmtN(passCount)}/${fmtN(totalTests)} tests ${testStatus}"
                        } catch (Exception ex) {
                            echo "Could not parse JUnit XML for description: ${ex.message}"
                        }
                    }

                    // Append coverage percentage (from LCOV lcov.info)
                    def lcovPath = "${outDir}/coverage/lcov.info"
                    if (fileExists(lcovPath)) {
                        try {
                            def pct = sh(
                                script: """
                                    TOTAL=\$(grep -E '^LF:' '${lcovPath}' | awk -F: '{s+=\$2} END{print s+0}')
                                    HIT=\$(grep -E '^LH:' '${lcovPath}'   | awk -F: '{s+=\$2} END{print s+0}')
                                    [ "\${TOTAL}" -gt 0 ] && \\
                                        awk "BEGIN { printf \\"%.1f\\", (\${HIT}/\${TOTAL})*100 }" || echo "N/A"
                                """,
                                returnStdout: true
                            ).trim()
                            if (pct != 'N/A') {
                                desc += " · ${pct}% cov"
                            }
                        } catch (Exception ex) {
                            echo "Could not read coverage for description: ${ex.message}"
                        }
                    }

                    currentBuild.description = desc
                    currentBuild.displayName = "#${env.BUILD_NUMBER} — ${params.SCAN_PATH}"
                } catch (Exception ex) {
                    echo "Could not set build metadata: ${ex.message}"
                }
                echo 'All stages passed. Artifacts and reports archived.'

                // Pipeline-of-Pipelines: trigger downstream job if configured.
                script {
                    if (params.DOWNSTREAM_JOB?.trim()) {
                        build job: params.DOWNSTREAM_JOB,
                              parameters: [
                                  string(name: 'UPSTREAM_JOB',   value: env.JOB_NAME),
                                  string(name: 'UPSTREAM_BUILD',  value: env.BUILD_NUMBER),
                                  string(name: 'ARTIFACT_PATH',   value: env.ARTIFACT_PATH ?: '')
                              ],
                              wait: false,
                              propagate: false
                    }
                }
            }
        }
        failure {
            echo 'Build failed — review the stage output above for details.'
        }
        always {
            // Bitbucket build status notification (no-op when plugin is absent).
            script {
                if (env.BITBUCKET_SOURCE_BRANCH || env.GIT_COMMIT) {
                    def state = currentBuild.result == 'SUCCESS' ? 'SUCCESSFUL' :
                                currentBuild.result == 'FAILURE'  ? 'FAILED' : 'STOPPED'
                    // Requires Bitbucket Build Status Notifier plugin
                    try {
                        bitbucketStatusNotify(
                            buildState: state,
                            buildKey:   env.JOB_NAME,
                            buildName:  "oxide-sloc CI #${env.BUILD_NUMBER}",
                            buildUrl:   env.BUILD_URL
                        )
                    } catch (e) {
                        echo "Bitbucket status notify skipped (plugin not installed): ${e.message}"
                    }
                }
            }
        }
        cleanup {
            // cleanup runs LAST — after success/failure/always — guaranteeing that
            // post { success } can still read result.json before the workspace is wiped.
            // cleanWs() removes the entire workspace so agents don't accumulate stale workspaces.
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
