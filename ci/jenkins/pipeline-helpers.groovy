// oxide-sloc Jenkins pipeline helpers
//
// Loaded by the canonical Jenkinsfile via:
//   h = load 'ci/jenkins/pipeline-helpers.groovy'
//
// Each function compiles as a separate class method, giving it its own
// 64 KB JVM bytecode budget and keeping the main WorkflowScript class
// well under the MethodTooLargeException threshold.
//
// Add new helper functions here rather than in the Jenkinsfile.

def runSetup() {
    // Disk preflight FIRST: fail fast on a low-space volume and prune the
    // persistent Rust cache if it has grown past its cap, so a build never dies
    // mid-run with ENOSPC and the cache that survives cleanWs() stays bounded.
    sh 'bash ci/jenkins/check-disk-space.sh'

    sh 'bash ci/jenkins/setup-toolchain.sh'
    sh 'bash ci/jenkins/setup-vendor.sh'

    // Relax artifact-viewer CSP so HTML report artifacts render with inline
    // styles and scripts.  Three-tier approach (each tier falls back silently):
    //   1. Direct System.setProperty — works when the Groovy sandbox is disabled
    //   2. Script Console REST API — requires credential 'jenkins-api-token'
    //   3. init.groovy.d — permanent fix: bash ci/jenkins/preflight.sh --install-csp
    def RELAXED_CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; " +
                      "img-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; " +
                      "font-src 'self' data:;"
    def cspSet = false

    try {
        System.setProperty('hudson.model.DirectoryBrowserSupport.CSP', RELAXED_CSP)
        echo 'Artifact-viewer CSP relaxed (direct System.setProperty).'
        cspSet = true
    } catch (Exception ex) {
        echo "Direct CSP set blocked (sandbox active): ${ex.message}"
    }

    if (!cspSet) {
        try {
            withCredentials([string(credentialsId: 'jenkins-api-token',
                                    variable:      'JEN_API_TOK')]) {
                if (env.JEN_API_TOK?.trim()) {
                    def base = (env.BUILD_URL ?: '').replaceAll('/job/.*', '').replaceAll('/+$', '')
                    if (base) {
                        withEnv(["SLOC_JENKINS_BASE=${base}",
                                 "SLOC_CSP=${RELAXED_CSP}"]) {
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
                                echo "Artifact-viewer CSP relaxed (Script Console API)."
                            '''
                        }
                    }
                } else {
                    echo 'jenkins-api-token not configured and Groovy sandbox is active.'
                    echo 'To fix permanently: bash ci/jenkins/preflight.sh --install-csp'
                    echo 'Or disable "Use Groovy Sandbox" in the pipeline job configuration.'
                }
            }
        } catch (Exception ex) {
            echo "CSP setup via API (non-fatal): ${ex.message}"
        }
    }
}

def runUnitTests() {
    def outDir     = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    def resultsDir = "${outDir}/test-results"
    sh "mkdir -p '${resultsDir}'"

    def useNextest = false
    if (params.TEST_RUNNER == 'cargo-nextest') {
        def alreadyInstalled = sh(
            script: 'cargo nextest --version >/dev/null 2>&1',
            returnStatus: true
        ) == 0
        if (!alreadyInstalled) {
            echo 'cargo-nextest not found — attempting offline install from vendor...'
            def installed = sh(
                script: 'cargo install --offline cargo-nextest 2>&1 | tail -5',
                returnStatus: true
            ) == 0
            if (installed) {
                echo 'cargo-nextest installed from vendor successfully.'
                useNextest = true
            } else {
                echo 'WARNING: cargo-nextest unavailable (not on PATH and not in vendor).'
                echo '  JUnit XML output will not be produced this run.'
                echo '  To enable: cargo install cargo-nextest  on the agent (then re-run install-rust-cache.sh).'
                echo '  Falling back to cargo test.'
            }
        } else {
            useNextest = true
        }
    }

    if (useNextest) {
        def failFastFlag = params.TEST_FAIL_FAST ? '--fail-fast' : '--no-fail-fast'
        sh """
            cargo nextest run --workspace ${failFastFlag} --profile ci \
                2>&1 | tee '${resultsDir}/nextest-output.txt'
        """
        // nextest writes JUnit XML into the profile store dir
        // (target/nextest/ci/junit.xml), NOT the workspace root. Move from there;
        // fall back to a search in case a custom CARGO_TARGET_DIR relocates it.
        sh """
            if [ -f target/nextest/ci/junit.xml ]; then
                mv -f target/nextest/ci/junit.xml '${resultsDir}/junit.xml'
            else
                found=\$(find . -path '*/nextest/ci/junit.xml' -print -quit 2>/dev/null)
                [ -n "\$found" ] && mv -f "\$found" '${resultsDir}/junit.xml' || true
            fi
        """
        if (params.PUBLISH_TEST_RESULTS) {
            // Guarded so a controller WITHOUT the JUnit plugin still passes — the
            // junit.xml is archived regardless, so nothing is lost but the sidebar
            // "Test Result" view. Throwable (not Exception): a missing step throws
            // NoSuchMethodError, which is an Error.
            try {
                junit testResults:          "${params.OUTPUT_SUBDIR}/test-results/junit.xml",
                      allowEmptyResults:    true,
                      skipPublishingChecks: false
            } catch (Throwable t) {
                echo "junit publish skipped (JUnit plugin not installed): ${t.message}"
            }
        }
    } else {
        def failFastFlag = params.TEST_FAIL_FAST ? '' : '--no-fail-fast'
        sh "cargo test --workspace ${failFastFlag}"
    }
}

def runCoverage() {
    def outDir      = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    def coverageDir = "${outDir}/coverage"
    sh "mkdir -p '${coverageDir}'"

    sh '''
        if ! cargo llvm-cov --version >/dev/null 2>&1; then
            echo "Installing cargo-llvm-cov from vendor (offline)..."
            cargo install --offline cargo-llvm-cov || \
                echo "WARNING: cargo-llvm-cov unavailable; tarpaulin fallback will be used."
        fi
        rustup component add llvm-tools 2>/dev/null || true
    '''

    sh "bash ci/sonar/generate-coverage.sh '${coverageDir}'"

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

    def threshold = params.COVERAGE_THRESHOLD?.trim()?.isDouble()
                        ? params.COVERAGE_THRESHOLD.trim().toDouble()
                        : (params.COVERAGE_THRESHOLD?.trim()?.isInteger()
                            ? params.COVERAGE_THRESHOLD.trim().toInteger() as Double
                            : 0.0)

    def lcovFile      = "${params.OUTPUT_SUBDIR}/coverage/lcov.info"

    // Feed the Jenkins Coverage view from LCOV only. cargo-llvm-cov's Cobertura
    // XML (sonar-coverage.xml) contains a duplicate element that the Coverage
    // plugin's CoberturaParser rejects, which threw and dropped the whole view;
    // lcov.info already provides line/branch/function coverage. sonar-coverage.xml
    // is still generated + archived for SonarQube — it's just not fed to Jenkins.
    def tools = []
    if (fileExists("${env.WORKSPACE}/${lcovFile}")) {
        tools << [parser: 'LCOV', pattern: lcovFile]
    }

    if (tools.isEmpty()) {
        echo 'WARNING: No coverage data files found — recordCoverage skipped.'
    } else {
        def gates = []
        if (threshold > 0) {
            gates << [threshold: threshold, metric: 'LINE',
                      baseline: 'PROJECT', criticality: 'FAILURE']
            gates << [threshold: threshold * 0.7, metric: 'BRANCH',
                      baseline: 'PROJECT', criticality: 'UNSTABLE']
        }
        // Guarded: without the Coverage plugin the lcov/cobertura files are still
        // archived; only the "Coverage" trend view is skipped.
        try {
            recordCoverage(
                tools:               tools,
                id:                  'oxide-sloc-coverage',
                name:                'Coverage',
                sourceCodeRetention: 'EVERY_BUILD',
                qualityGates:        gates
            )
        } catch (Throwable t) {
            // Could be a missing Coverage plugin OR a parser error — log the real
            // reason rather than assuming the plugin is absent.
            echo "recordCoverage skipped (Coverage plugin missing, or report parse error): ${t.message}"
        }
    }

    if (fileExists("${coverageDir}/html/index.html")) {
        publishHtmlSafe([
            allowMissing         : false,
            alwaysLinkToLastBuild: true,
            keepAll              : false,
            reportDir            : "${params.OUTPUT_SUBDIR}/coverage/html",
            reportFiles          : 'index.html',
            reportName           : 'Coverage Source',
        ])
    } else {
        echo 'Annotated HTML source report not available for this run.'
    }
}

// Publish an HTML report, degrading cleanly when the HTML Publisher plugin is
// absent: the report dir is already archived by archiveArtifacts, so without the
// plugin you simply lose the left-sidebar link, not the report. Throwable, not
// Exception — a missing publishHTML step throws NoSuchMethodError (an Error).
def publishHtmlSafe(Map target) {
    try {
        publishHTML(target: target)
    } catch (Throwable t) {
        echo "publishHTML '${target.reportName}' skipped (HTML Publisher plugin not installed); " +
             "the report is still available under Build Artifacts. (${t.message})"
    }
}

def runAnalyze() {
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
    if (params.ENABLED_LANGUAGES) {
        params.ENABLED_LANGUAGES.tokenize(',').each { l ->
            if (!(l.trim() ==~ /^[a-zA-Z0-9\+\#]+$/)) {
                error("ENABLED_LANGUAGES contains invalid value: ${l.trim()}")
            }
        }
    }
    if (params.ACTIVITY_WINDOW?.trim() && !(params.ACTIVITY_WINDOW.trim() ==~ /^[0-9]{1,4}$/)) {
        error("ACTIVITY_WINDOW must be a number of days (0-3650): ${params.ACTIVITY_WINDOW}")
    }

    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    sh "mkdir -p '${outDir}'"

    // scanRoot is where the project-under-analysis lives: the workspace root for a
    // self-scan, or ./_target when TARGET_REPO_URL was checked out (set in Checkout).
    // All scan commands and git-based features resolve against it.
    def scanRoot         = env.SCAN_ROOT?.trim() ?: env.WORKSPACE
    def scanningExternal = scanRoot != env.WORKSPACE

    // Resolve SCAN_PATH against scanRoot ONLY when scanning an external project, so a
    // plain self-scan keeps its exact previous behaviour (relative path, cwd=WORKSPACE).
    def effScan = params.SCAN_PATH?.trim() ?: '.'
    if (scanningExternal) {
        effScan = effScan.startsWith('/') ? effScan : "${scanRoot}/${effScan}"
        // Fail fast with a helpful message when a SCAN_PATH subtree does not exist
        // in the target repo (a blank SCAN_PATH scans the whole repo and never trips this).
        if (!fileExists(effScan)) {
            error("SCAN_PATH '${params.SCAN_PATH}' was not found in the target repo (${scanRoot}). " +
                  "Leave SCAN_PATH BLANK to scan the whole repo, or set an existing subtree like 'src'.")
        }
    }

    // Derive a project slug that matches the local-run naming convention:
    //   {repo-name}_{short-sha}  (e.g. airgap-devkit_a78a632)
    // Name comes from the last path segment of the scanned repo's URL (strip .git).
    // When scanning an external project that is TARGET_REPO_URL, otherwise REPO_URL.
    def slugSource = scanningExternal ? params.TARGET_REPO_URL : params.REPO_URL
    def repoSlug = (slugSource?.trim()
                        ? slugSource.trim()
                              .replaceAll(/\.git$/, '')
                              .replaceAll(/.*[\/:]/, '')
                              .replaceAll(/[^a-zA-Z0-9_\-]/, '-')
                              .replaceAll(/-+/, '-')
                              .replaceAll(/^-|-$/, '')
                        : '') ?: 'project'
    // Short SHA: from GIT_COMMIT (the tooling checkout) for a self-scan, or from the
    // target checkout's HEAD when scanning an external project.
    def shortSha
    if (scanningExternal) {
        shortSha = sh(script: "git -C '${scanRoot}' rev-parse --short HEAD 2>/dev/null || echo unknown",
                      returnStdout: true).trim()
    } else {
        def rawSha = env.GIT_COMMIT?.trim() ?: ''
        shortSha = (rawSha.length() >= 7)
                        ? rawSha[0..6]
                        : sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
    }
    def projectSlug = "${repoSlug}_${shortSha}"
    env.SLOC_PROJECT = projectSlug

    def configArg    = (params.CI_PRESET != 'none')
                        ? "--config 'ci/sloc-ci-${params.CI_PRESET}.toml'"
                        : ''
    def jsonArg      = "--json-out  '${outDir}/result_${projectSlug}.json'"
    def csvArg       = "--csv-out   '${outDir}/report_${projectSlug}.csv'"
    def xlsxArg      = "--xlsx-out  '${outDir}/report_${projectSlug}.xlsx'"
    def htmlArg      = params.GENERATE_HTML       ? "--html-out '${outDir}/report_${projectSlug}.html'" : ''
    def pdfArg       = params.GENERATE_PDF        ? "--pdf-out  '${outDir}/report_${projectSlug}.pdf'"  : ''
    def docArg       = params.DOCSTRINGS_AS_CODE  ? '--python-docstrings-as-code'        : ''
    def symlinkArg   = params.FOLLOW_SYMLINKS     ? '--follow-symlinks'                  : ''
    def noIgnoreArg  = params.NO_IGNORE_FILES     ? '--no-ignore-files'                  : ''
    def submodArg    = params.SUBMODULE_BREAKDOWN ? '--submodule-breakdown'              : ''
    def styleColArg  = (params.STYLE_COL_THRESHOLD?.trim() && params.STYLE_COL_THRESHOLD.trim() != '80')
                        ? "--style-col-threshold '${params.STYLE_COL_THRESHOLD.trim()}'"
                        : ''
    // Git Hotspots window. On by default (the binary uses 90 when omitted); only emit the flag
    // when the operator picked a non-default value, including 0 to disable.
    def activityArg  = (params.ACTIVITY_WINDOW?.trim() && params.ACTIVITY_WINDOW.trim() != '90')
                        ? "--activity-window '${params.ACTIVITY_WINDOW.trim()}'"
                        : ''
    // Outputs that mirror the web UI artifact layout: scan-config JSON and
    // per-submodule HTML reports (sub_<name>.html in the output directory).
    def scanConfigArg = "--scan-config-out '${outDir}/scan-config_${projectSlug}.json'"
    def subHtmlArg    = params.SUBMODULE_BREAKDOWN
                        ? "--sub-html-out-dir '${outDir}'"
                        : ''

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
    withEnv(["SCAN_PATH=${effScan}"]) {
        sh '''
            "${BINARY}" analyze "${SCAN_PATH}" --plain ''' + configArg + '''
        '''
    }

    // b. Main artifact run — JSON, CSV, XLSX always written; HTML and PDF are optional.
    // Pass --git-branch explicitly so the report shows the correct branch name even
    // when Jenkins performs a detached-HEAD checkout (GIT_BRANCH = "origin/main").
    def rawBranch  = env.GIT_BRANCH ?: ''
    def branchName = rawBranch.replaceAll('^origin/', '').replaceAll('^refs/heads/', '').trim()
    def branchArg  = branchName ? "--git-branch '${branchName}'" : ''

    withEnv([
        "SCAN_PATH=${effScan}",
        "REPORT_TITLE=${params.REPORT_TITLE}",
        "MIXED_LINE_POLICY=${params.MIXED_LINE_POLICY}",
    ]) {
        sh '''
            "${BINARY}" analyze "${SCAN_PATH}" \
                --report-title "${REPORT_TITLE}" \
                --mixed-line-policy "${MIXED_LINE_POLICY}" \
                ''' + "${configArg} ${docArg} ${symlinkArg} ${noIgnoreArg} ${submodArg} ${styleColArg} ${activityArg}" + ''' \
                ''' + "${langArgs} ${includeArgs} ${excludeArgs} ${branchArg}" + ''' \
                ''' + "${jsonArg} ${csvArg} ${xlsxArg} ${htmlArg} ${pdfArg}" + ''' \
                ''' + "${scanConfigArg} ${subHtmlArg}" + '''
        '''
    }

    sh "test -s '${outDir}/result_${projectSlug}.json'"
    sh "test -s '${outDir}/report_${projectSlug}.csv'"
    sh "test -s '${outDir}/report_${projectSlug}.xlsx'"
    if (params.GENERATE_HTML) { sh "test -s '${outDir}/report_${projectSlug}.html'" }

    // c. Per-file breakdown
    withEnv(["SCAN_PATH=${effScan}"]) {
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

    // e. Extract inline CSS/JS so the report renders under Jenkins's default CSP.
    if (params.GENERATE_HTML) {
        sh "python3 ci/jenkins/extract-report-assets.py '${outDir}/report_${projectSlug}.html' || true"
    }

    // f. Mixed-line policy matrix — spot-checks all four policies
    for (def policy in ['code-only', 'code-and-comment', 'comment-only', 'separate-mixed-category']) {
        withEnv(["SCAN_PATH=${effScan}"]) {
            sh '''
                "${BINARY}" analyze "${SCAN_PATH}" --plain --mixed-line-policy ''' + policy + '''
            '''
        }
    }
}

def runArchivePublish() {
    def outDir   = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    def proj     = env.SLOC_PROJECT ?: 'project'
    def jobSlug  = (env.JOB_NAME?.replaceAll('[^a-zA-Z0-9_\\-]', '_') ?: 'oxide-sloc')
    def histFile = "${env.HOME}/.oxide-sloc-history/${jobSlug}.csv"

    sh "python3 ci/jenkins/generate-trend-csv.py '${outDir}' '${proj}' '${histFile}'"

    // Detect what this build is allowed to do (system-admin ⇒ may install the
    // richer visualization plugins; otherwise degrade to the native dashboard).
    // The auth-API probe uses the 'jenkins-api-token' credential when present;
    // every step here is best-effort and never fails the build.
    try {
        def base = (env.BUILD_URL ?: '').replaceAll('/job/.*', '').replaceAll('/+$', '')
        // 'jenkins-api-token' is a secret-text credential (a token); the API user
        // defaults to 'admin' to match runSetup, overridable via JENKINS_API_USER.
        withCredentials([string(credentialsId: 'jenkins-api-token',
                                variable: 'SLOC_JTOKEN')]) {
            // The token must be read as $SLOC_JTOKEN INSIDE sh — a withCredentials
            // binding is injected into the shell env (masked) but is NOT visible via
            // ${env.SLOC_JTOKEN} in Groovy. Interpolating it in Groovy sent an empty
            // token (so the probe ran anonymously and the dashboard wrongly showed
            // "degraded / read-only") and would also defeat Jenkins' secret masking.
            withEnv(["JENKINS_BASE_URL=${base}",
                     "JENKINS_USER=${env.JENKINS_API_USER ?: 'admin'}"]) {
                sh "JENKINS_AUTH_TOKEN=\"\$SLOC_JTOKEN\" python3 ci/jenkins/detect-capabilities.py '${outDir}' || true"
                sh "JENKINS_AUTH_TOKEN=\"\$SLOC_JTOKEN\" bash ci/jenkins/install-plugins.sh '${outDir}' || true"
            }
        }
    } catch (Exception ex) {
        // No 'jenkins-api-token' credential — still probe anonymously so the
        // dashboard can show the correct (degraded) banner.
        echo "Capability probe running without API credentials: ${ex.message}"
        def base = (env.BUILD_URL ?: '').replaceAll('/job/.*', '').replaceAll('/+$', '')
        withEnv(["JENKINS_BASE_URL=${base}"]) {
            sh "python3 ci/jenkins/detect-capabilities.py '${outDir}' || true"
        }
    }

    // Generate the dashboard (and the curated ci-report/ + html-report/ bundles)
    // BEFORE archiving so the bundle layout is present for both archive + publish.
    def dashboardBuilt = false
    try {
        sh "python3 ci/jenkins/generate-dashboard.py '${outDir}' '${proj}' '${histFile}'"
        dashboardBuilt = fileExists("${outDir}/ci-report/index.html")
    } catch (Exception ex) {
        echo "generate-dashboard.py did not run (Python 3 unavailable or script error): ${ex.message}"
    }

    // Archive everything except the curated bundle dirs — those are duplicated
    // copies published separately below, so keeping them out keeps the archive lean.
    archiveArtifacts artifacts: "${params.OUTPUT_SUBDIR}/**",
        excludes: "${params.OUTPUT_SUBDIR}/ci-report/**,${params.OUTPUT_SUBDIR}/html-report/**",
        fingerprint: true,
        allowEmptyArchive: true

    // Zip names come from the report name (htmlpublisher sanitises it), so we use
    // project-scoped, space/em-dash-free names → e.g. OxideSLOC_CI_Report_<proj>.zip.
    // reportFiles is always index.html, so the zip has one obvious entry point.
    if (dashboardBuilt) {
        publishHtmlSafe([
            allowMissing         : true,
            alwaysLinkToLastBuild: true,
            keepAll              : false,
            reportDir            : "${params.OUTPUT_SUBDIR}/ci-report",
            reportFiles          : "index.html",
            reportName           : "OxideSLOC_CI_Report_${proj}",
        ])
    }

    if (params.GENERATE_HTML && fileExists("${outDir}/html-report/index.html")) {
        publishHtmlSafe([
            allowMissing         : false,
            alwaysLinkToLastBuild: true,
            keepAll              : false,
            reportDir            : "${params.OUTPUT_SUBDIR}/html-report",
            reportFiles          : "index.html",
            reportName           : "OxideSLOC_HTML_Report_${proj}",
        ])
    }

    try {
        if (fileExists("${env.WORKSPACE}/${params.OUTPUT_SUBDIR}/summary.csv")) {
            plot(
                csvFileName: 'sloc-trend-summary.csv',
                csvSeries:   [[file: "${params.OUTPUT_SUBDIR}/summary.csv",
                               url: '', displayTableFlag: false,
                               inclusionFlag: 'OFF', exclusionValues: '']],
                group:       'SLOC Trends',
                title:       'SLOC Totals Over Time',
                style:       'line',
                yaxis:       'Lines',
                numBuilds:   '50',
                keepRecords: true,
                useDescr:    true
            )
        }
        if (fileExists("${env.WORKSPACE}/${params.OUTPUT_SUBDIR}/per_language.csv")) {
            plot(
                csvFileName: 'sloc-trend-per-language.csv',
                csvSeries:   [[file: "${params.OUTPUT_SUBDIR}/per_language.csv",
                               url: '', displayTableFlag: false,
                               inclusionFlag: 'OFF', exclusionValues: '']],
                group:       'SLOC Trends',
                title:       'Per-Language Code Lines',
                style:       'bar',
                yaxis:       'Code Lines',
                numBuilds:   '50',
                keepRecords: true,
                useDescr:    true
            )
        }
        if (params.COVERAGE_STANDALONE &&
                fileExists("${env.WORKSPACE}/${params.OUTPUT_SUBDIR}/coverage.csv")) {
            plot(
                csvFileName: 'sloc-trend-coverage.csv',
                csvSeries:   [[file: "${params.OUTPUT_SUBDIR}/coverage.csv",
                               url: '', displayTableFlag: false,
                               inclusionFlag: 'OFF', exclusionValues: '']],
                group:       'SLOC Trends',
                title:       'Line Coverage % Over Time',
                style:       'line',
                yaxis:       'Coverage %',
                numBuilds:   '50',
                keepRecords: true,
                useDescr:    true
            )
        }
        if (fileExists("${env.WORKSPACE}/${params.OUTPUT_SUBDIR}/style_analysis.csv")) {
            plot(
                csvFileName: 'sloc-trend-style.csv',
                csvSeries:   [[file: "${params.OUTPUT_SUBDIR}/style_analysis.csv",
                               url: '', displayTableFlag: false,
                               inclusionFlag: 'OFF', exclusionValues: '']],
                group:       'SLOC Trends',
                title:       'Code Style N-Col Compliance % Over Time',
                style:       'line',
                yaxis:       'Compliance %',
                numBuilds:   '50',
                keepRecords: true,
                useDescr:    true
            )
        }
    } catch (Throwable ex) {
        // Throwable, not Exception: a missing plot step throws NoSuchMethodError
        // (an Error). Without the plugin the trend CSVs are still archived.
        echo "Plot trend charts skipped (install the 'plot' plugin to enable): ${ex.message}"
    }
}

def runPushArtifacts() {
    def allowedTypes = [
        'artifactory', 'nexus', 'nexus2', 's3', 'minio', 'azure-blob', 'generic-http'
    ]
    if (!allowedTypes.contains(params.ARTIFACT_REPO_TYPE)) {
        error("Invalid ARTIFACT_REPO_TYPE: ${params.ARTIFACT_REPO_TYPE}")
    }

    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"

    def repoPath = params.ARTIFACT_REPO_PATH
        .replace('${JOB_NAME}',     env.JOB_NAME    ?: 'unknown-job')
        .replace('${BUILD_NUMBER}', env.BUILD_NUMBER ?: '0')

    def filesToPush = []
    def proj = env.SLOC_PROJECT ?: 'project'
    if (params.ARTIFACT_PUSH_JSON)                           filesToPush << "result_${proj}.json"
    if (params.ARTIFACT_PUSH_CSV)                            filesToPush << "report_${proj}.csv"
    if (params.ARTIFACT_PUSH_XLSX)                           filesToPush << "report_${proj}.xlsx"
    if (params.ARTIFACT_PUSH_HTML && params.GENERATE_HTML)   filesToPush << "report_${proj}.html"
    if (params.ARTIFACT_PUSH_PDF  && params.GENERATE_PDF)    filesToPush << "report_${proj}.pdf"

    if (params.ARTIFACT_PUSH_BINARY) {
        def binaryName = isUnix() ? 'oxide-sloc' : 'oxide-sloc.exe'
        def binaryPath = "${env.WORKSPACE}/target/release/${binaryName}"
        if (fileExists(binaryPath)) {
            sh "cp '${binaryPath}' '${outDir}/${binaryName}'"
            filesToPush << binaryName
        } else {
            echo "WARNING: binary not found at ${binaryPath} — skipping binary push."
        }
    }

    if (params.ARTIFACT_PUSH_JUNIT
            && params.PUBLISH_TEST_RESULTS
            && params.TEST_RUNNER == 'cargo-nextest') {
        def junitPath = "${env.WORKSPACE}/test-results/junit.xml"
        if (fileExists(junitPath)) {
            sh "cp '${junitPath}' '${outDir}/junit.xml'"
            filesToPush << 'junit.xml'
        } else {
            echo "WARNING: junit.xml not found at ${junitPath} — skipping junit push."
        }
    }

    if (params.ARTIFACT_PUSH_COVERAGE && params.COVERAGE_STANDALONE) {
        [['coverage/lcov.info', 'lcov.info'],
         ['coverage/sonar-coverage.xml', 'sonar-coverage.xml']].each { src, dst ->
            def srcPath = "${env.WORKSPACE}/${src}"
            if (fileExists(srcPath)) {
                sh "cp '${srcPath}' '${outDir}/${dst}'"
                filesToPush << dst
            }
        }
    }

    if (params.ARTIFACT_PUSH_DIFF && params.GIT_REF?.trim()) {
        ['diff.json', 'diff.csv'].each { f ->
            if (fileExists("${outDir}/${f}")) filesToPush << f
        }
    }

    if (filesToPush.isEmpty()) {
        echo 'No artifact files selected for push — skipping.'
        return
    }

    try {
        withCredentials([
            string(credentialsId: 'SLOC_ARTIFACT_REPO_USER', variable: 'SLOC_AR_USER'),
            string(credentialsId: 'SLOC_ARTIFACT_REPO_PASS', variable: 'SLOC_AR_PASS'),
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
                "ARTIFACT_GENERATE_MANIFEST=${params.ARTIFACT_GENERATE_MANIFEST}",
            ]) {
                sh 'bash ci/artifact-push.sh'
            }
        }
    } catch (Exception ex) {
        echo "WARNING: Artifact repo credentials (SLOC_ARTIFACT_REPO_USER / SLOC_ARTIFACT_REPO_PASS) not found in Jenkins credential store — attempting unauthenticated push. (${ex.message})"
        withEnv([
            "ARTIFACT_REPO_TYPE=${params.ARTIFACT_REPO_TYPE}",
            "ARTIFACT_REPO_URL=${params.ARTIFACT_REPO_URL}",
            "ARTIFACT_REPO_PATH=${repoPath}",
            "ARTIFACT_REPO_EXTRA=${params.ARTIFACT_REPO_EXTRA ?: ''}",
            "ARTIFACT_DIR=${outDir}",
            "ARTIFACT_FILES=${filesToPush.join(' ')}",
            "ARTIFACT_REPO_USER=",
            "ARTIFACT_REPO_PASS=",
            "ARTIFACT_GENERATE_MANIFEST=${params.ARTIFACT_GENERATE_MANIFEST}",
        ]) {
            sh 'bash ci/artifact-push.sh'
        }
    }
}

def runGitRefCompare() {
    withEnv([
        "GIT_REF=${params.GIT_REF}",
        "COMPARE_TO_REF=${params.COMPARE_TO_REF}",
        "COMPARE_TO_PREV_TAG=${params.COMPARE_TO_PREV_TAG}",
        "OUTPUT_SUBDIR=${params.OUTPUT_SUBDIR}",
        "SCAN_ROOT=${env.SCAN_ROOT ?: env.WORKSPACE}",
    ]) {
        sh '''
            OUT="${WORKSPACE}/${OUTPUT_SUBDIR}"
            BINARY="${WORKSPACE}/target/release/oxide-sloc"
            # Git operations target the scanned repo (workspace root for a self-scan,
            # ./_target when TARGET_REPO_URL was checked out).
            REPO="${SCAN_ROOT:-$WORKSPACE}"

            # Resolve baseline ref
            if [ "${COMPARE_TO_PREV_TAG:-false}" = "true" ]; then
                CURRENT_TAG=$(git -C "${REPO}" tag --sort=-version:refname | head -1)
                BASELINE_TAG=$(git -C "${REPO}" tag --sort=-version:refname | grep -v "^${CURRENT_TAG}$" | head -1)
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
                CURRENT_JSON="${OUT}/result_${SLOC_PROJECT:-project}.json"
            fi
            if [ ! -f "${CURRENT_JSON}" ]; then
                echo "No current scan JSON found — cannot compare."
                exit 1
            fi

            echo "=== Scanning baseline: ${BASELINE_REF} ==="
            WT_BASE="${WORKSPACE}/.wt-baseline"
            git -C "${REPO}" worktree add --detach "${WT_BASE}" "${BASELINE_REF}"

            "${BINARY}" analyze "${WT_BASE}" \
                --json-out  "${OUT}/baseline-scan.json" \
                --report-title "Baseline: ${BASELINE_REF}" \
                --plain

            git -C "${REPO}" worktree remove --force "${WT_BASE}" || true

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

def runPostSuccess() {
    try {
        def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
        def proj   = env.SLOC_PROJECT
                        ?: (params.SCAN_PATH?.trim()?.split('[/\\\\]') as List)?.last()
                        ?: 'project'
        def result = readJSON file: "${outDir}/result_${proj}.json"
        def t      = result.summary_totals

        // A human label for the build row: the SCAN_PATH subtree if set, else the
        // target repo name (external scan), else "whole repo" (self-scan). SCAN_PATH
        // is commonly blank now (blank = whole repo), so never show an empty label.
        def scanLabel = params.SCAN_PATH?.trim()
        if (!scanLabel) {
            def tRepo = params.TARGET_REPO_URL?.trim()
            scanLabel = tRepo
                ? tRepo.replaceAll(/\.git$/, '').replaceAll(/.*[\/:]/, '')
                : 'whole repo'
        }

        def fmtN = { n ->
            long v = n as long
            long a = Math.abs(v)
            if (a >= 1_000_000L) {
                String s = String.format('%.1f', v / 1_000_000.0) + 'M'
                return s.replace('.0M', 'M')
            }
            if (a >= 10_000L) return "${Math.round(v / 1_000.0d)}K"
            return String.format('%,d', v)
        }
        // Plain one-line fallback (used if the rich generator can't run).
        def desc = "${fmtN(t.code_lines)} code · " +
                   "${fmtN(t.comment_lines)} cmts · " +
                   "${fmtN(t.blank_lines)} blank · " +
                   "${fmtN(t.files_analyzed)} files | ${scanLabel}"

        // Capture the sub-metrics so the rich summary generator can lay them out.
        def styleStr = ''
        def testsStr = ''
        def covStr   = ''

        def ss = result.style_summary
        if (ss) {
            def colThreshold = ss.col_threshold ?: 80
            def colPct       = ss.line_col_compliant_pct ?: 0
            styleStr = "${ss.common_indent_style} · ${colPct}% ${colThreshold}-col"
            desc += " · Style: ${styleStr}"
        }

        def junitPath = "${outDir}/test-results/junit.xml"
        if (fileExists(junitPath)) {
            try {
                def junitXml   = readFile(junitPath)
                def tm = junitXml =~ /tests="(\d+)"/
                def fm = junitXml =~ /failures="(\d+)"/
                def em = junitXml =~ /errors="(\d+)"/
                def totalTests = tm ? (tm[0][1] as long) : 0L
                def failCount  = fm ? (fm[0][1] as long) : 0L
                def errCount   = em ? (em[0][1] as long) : 0L
                def passCount  = Math.max(0L, totalTests - failCount - errCount)
                def testStatus = (failCount == 0 && errCount == 0) ? 'OK' : "FAIL(${fmtN(failCount)})"
                testsStr = "${passCount}/${totalTests}"
                desc += " · ${testsStr} tests ${testStatus}"
            } catch (Exception ex) {
                echo "Could not parse JUnit XML for description: ${ex.message}"
            }
        }

        def lcovPath = "${outDir}/coverage/lcov.info"
        if (fileExists(lcovPath)) {
            try {
                def pct = sh(
                    script: """
                        TOTAL=\$(grep -E '^LF:' '${lcovPath}' | awk -F: '{s+=\$2} END{print s+0}')
                        HIT=\$(grep -E '^LH:' '${lcovPath}'   | awk -F: '{s+=\$2} END{print s+0}')
                        [ "\${TOTAL}" -gt 0 ] && \
                            awk "BEGIN { printf \\"%.1f\\", (\${HIT}/\${TOTAL})*100 }" || echo "N/A"
                    """,
                    returnStdout: true
                ).trim()
                if (pct != 'N/A') {
                    covStr = pct
                    desc += " · ${pct}% cov"
                }
            } catch (Exception ex) {
                echo "Could not read coverage for description: ${ex.message}"
            }
        }

        // Rich, multi-line Unicode bar-chart description + HTML summary panel.
        // build-summary.py renders both; the .txt is set as the description
        // (renders under the default Plain-text formatter — newlines + block
        // glyphs, no HTML needed) and the .html feeds the badge summary box.
        def richDesc = desc
        try {
            withEnv(["SLOC_SCAN_PATH=${scanLabel}",
                     "SLOC_TESTS=${testsStr}",
                     "SLOC_COV=${covStr}",
                     "SLOC_STYLE=${styleStr}"]) {
                sh """
                    python3 ci/jenkins/build-summary.py \
                        '${outDir}/result_${proj}.json' '${outDir}' \
                        --scan-path "\${SLOC_SCAN_PATH}" \
                        --tests "\${SLOC_TESTS}" \
                        --coverage "\${SLOC_COV}" \
                        --style "\${SLOC_STYLE}" >/dev/null || true
                """
            }
            if (fileExists("${outDir}/build-description.txt")) {
                richDesc = readFile(file: "${outDir}/build-description.txt")
            }
        } catch (Exception ex) {
            echo "Rich build summary generation skipped: ${ex.message}"
        }

        currentBuild.description = richDesc
        currentBuild.displayName = "#${env.BUILD_NUMBER} — ${scanLabel}"

        // A boxed HTML summary panel (metric table + coloured language bars) on
        // the build page, via the badge plugin's createSummary. Catch Throwable,
        // not Exception: a missing pipeline step (no badge plugin) throws
        // NoSuchMethodError (an Error), which would otherwise flip a successful
        // build to FAILURE. Degrades to the Unicode description above.
        try {
            if (fileExists("${outDir}/build-summary.html")) {
                def panel = readFile(file: "${outDir}/build-summary.html")
                createSummary(icon: 'symbol-analytics-outline plugin-ionicons-api',
                              text: panel)
            }
        } catch (Throwable ignore) {
            // badge/summary plugin not installed — non-fatal by design.
        }

        // Compact headline badge on the run row itself (also badge-plugin gated).
        try {
            addBadge(icon: 'symbol-analytics-outline plugin-ionicons-api',
                     text: "oxide-sloc: ${fmtN(t.code_lines)} code · " +
                           "${fmtN(t.files_analyzed)} files")
        } catch (Throwable ignore) {
            // badge plugin not installed — non-fatal by design.
        }
    } catch (Throwable ex) {
        echo "Could not set build metadata: ${ex.message}"
    }
    echo 'All stages passed. Artifacts and reports archived.'

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

def runBitbucketNotify() {
    def result = currentBuild.result ?: 'SUCCESS'
    def state  = result == 'SUCCESS' ? 'SUCCESSFUL' :
                 result == 'FAILURE' ? 'FAILED' : 'STOPPED'

    // 1. Plugin path — used when the bitbucket-build-status-notifier plugin is
    //    installed (i.e. a system-admin build was able to enable it).
    if (env.BITBUCKET_SOURCE_BRANCH || env.GIT_COMMIT) {
        try {
            bitbucketStatusNotify(
                buildState: state,
                buildKey:   env.JOB_NAME,
                buildName:  "oxide-sloc CI #${env.BUILD_NUMBER}",
                buildUrl:   env.BUILD_URL
            )
        } catch (e) {
            echo "Bitbucket status notify via plugin skipped (plugin not installed): ${e.message}"
        }
    }

    // 2. Plugin-independent path — post the status + a link to the published
    //    report to Bitbucket, and upsert a Confluence summary page. Both are
    //    fully opt-in via credentials and no-op (exit 0) when unconfigured, so
    //    they work with or without the plugins and never fail the build.
    def proj      = env.SLOC_PROJECT ?: 'project'
    def reportUrl = env.BUILD_URL ? "${env.BUILD_URL}OxideSLOC_CI_Report_${proj}/" : ''
    def outDir    = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    def bbState   = result == 'FAILURE' ? 'FAILED' : 'SUCCESSFUL'

    try {
        withCredentials([string(credentialsId: 'bitbucket-build-token',
                                variable: 'SLOC_BB_TOKEN')]) {
            // Read the token as $SLOC_BB_TOKEN inside sh (masked) — a withCredentials
            // binding is not visible via ${env.SLOC_BB_TOKEN} in Groovy, so
            // interpolating it here would pass an empty token and the notifier would
            // silently treat itself as "not configured" and skip.
            withEnv(["BITBUCKET_BASE_URL=${env.BITBUCKET_BASE_URL ?: ''}",
                     "BITBUCKET_WORKSPACE=${env.BITBUCKET_WORKSPACE ?: ''}",
                     "BITBUCKET_REPO=${env.BITBUCKET_REPO ?: ''}",
                     "GIT_COMMIT=${env.GIT_COMMIT ?: ''}",
                     "BUILD_KEY=${env.JOB_NAME ?: 'oxide-sloc'}",
                     "BUILD_NAME=oxide-sloc CI #${env.BUILD_NUMBER}",
                     "REPORT_URL=${reportUrl}"]) {
                sh "BITBUCKET_TOKEN=\"\$SLOC_BB_TOKEN\" bash ci/jenkins/notify-bitbucket.sh ${bbState} || true"
            }
        }
    } catch (Exception ex) {
        echo "Bitbucket direct notify skipped (no 'bitbucket-build-token' credential): ${ex.message}"
    }

    try {
        withCredentials([string(credentialsId: 'confluence-api-token',
                                variable: 'SLOC_CF_TOKEN')]) {
            // Same masking rule: read $SLOC_CF_TOKEN inside sh, not via Groovy env.
            withEnv(["CONFLUENCE_BASE_URL=${env.CONFLUENCE_BASE_URL ?: ''}",
                     "CONFLUENCE_USER=${env.CONFLUENCE_USER ?: ''}",
                     "CONFLUENCE_SPACE_KEY=${env.CONFLUENCE_SPACE_KEY ?: ''}",
                     "CONFLUENCE_PARENT_ID=${env.CONFLUENCE_PARENT_ID ?: ''}",
                     "REPORT_URL=${reportUrl}"]) {
                sh "CONFLUENCE_TOKEN=\"\$SLOC_CF_TOKEN\" python3 ci/jenkins/notify-confluence.py '${outDir}' '${proj}' || true"
            }
        }
    } catch (Exception ex) {
        echo "Confluence notify skipped (no 'confluence-api-token' credential): ${ex.message}"
    }
}

return this
