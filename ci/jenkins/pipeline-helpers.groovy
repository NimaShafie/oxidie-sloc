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

    if (params.TEST_RUNNER == 'cargo-nextest') {
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
        sh "mv -f junit.xml '${resultsDir}/junit.xml' 2>/dev/null || true"
        if (params.PUBLISH_TEST_RESULTS) {
            junit testResults:         "${params.OUTPUT_SUBDIR}/test-results/junit.xml",
                  allowEmptyResults:   true,
                  skipPublishingChecks: false
        }
    } else {
        def failFastFlag = params.TEST_FAIL_FAST ? '' : '--no-fail-fast'
        sh """
            cargo test --workspace ${failFastFlag}
        """
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
            sourceCodeRetention: 'EVERY_BUILD',
            qualityGates:        gates
        )
    }

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

    def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    sh "mkdir -p '${outDir}'"

    def scanParts   = params.SCAN_PATH.trim().split('[/\\\\]') as List
    def projectSlug = (scanParts ? scanParts[-1] : params.SCAN_PATH.trim())
                        .replaceAll(/[^a-zA-Z0-9_\-]/, '-')
                        .replaceAll(/-+/, '-')
                        .replaceAll(/^-|-$/, '') ?: 'project'
    env.SLOC_PROJECT = projectSlug

    def configArg   = (params.CI_PRESET != 'none')
                        ? "--config 'ci/sloc-ci-${params.CI_PRESET}.toml'"
                        : ''
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
    // Pass --git-branch explicitly so the report shows the correct branch name even
    // when Jenkins performs a detached-HEAD checkout (GIT_BRANCH = "origin/main").
    def rawBranch  = env.GIT_BRANCH ?: ''
    def branchName = rawBranch.replaceAll('^origin/', '').replaceAll('^refs/heads/', '').trim()
    def branchArg  = branchName ? "--git-branch '${branchName}'" : ''

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
                ''' + "${langArgs} ${includeArgs} ${excludeArgs} ${branchArg}" + ''' \
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

    // e. Extract inline CSS/JS so the report renders under Jenkins's default CSP.
    if (params.GENERATE_HTML) {
        sh "python3 ci/jenkins/extract-report-assets.py '${outDir}/report_${projectSlug}.html' || true"
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

def runArchivePublish() {
    def outDir   = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
    def proj     = env.SLOC_PROJECT ?: 'project'
    def jobSlug  = (env.JOB_NAME?.replaceAll('[^a-zA-Z0-9_\\-]', '_') ?: 'oxide-sloc')
    def histFile = "${env.HOME}/.oxide-sloc-history/${jobSlug}.csv"

    sh "python3 ci/jenkins/generate-trend-csv.py '${outDir}' '${proj}' '${histFile}'"

    archiveArtifacts artifacts: "${params.OUTPUT_SUBDIR}/**",
        fingerprint: true,
        allowEmptyArchive: true

    try {
        sh "python3 ci/jenkins/generate-dashboard.py '${outDir}' '${proj}' '${histFile}'"
        if (fileExists("${outDir}/dashboard_${proj}.html")) {
            publishHTML(target: [
                allowMissing         : true,
                alwaysLinkToLastBuild: true,
                keepAll              : true,
                reportDir            : params.OUTPUT_SUBDIR,
                reportFiles          : "dashboard_${env.SLOC_PROJECT ?: 'project'}.html",
                reportName           : "OxideSLOC — Jenkins CI Report",
            ])
        }
    } catch (Exception ex) {
        echo "generate-dashboard.py did not run (Python 3 unavailable or script error): ${ex.message}"
    }

    if (params.GENERATE_HTML) {
        publishHTML(target: [
            allowMissing         : false,
            alwaysLinkToLastBuild: true,
            keepAll              : true,
            reportDir            : params.OUTPUT_SUBDIR,
            reportFiles          : "report_${env.SLOC_PROJECT ?: 'project'}.html",
            reportName           : "OxideSLOC — Jenkins HTML Report",
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
    } catch (Exception ex) {
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
    ]) {
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
                CURRENT_JSON="${OUT}/result_${SLOC_PROJECT:-project}.json"
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

def runPostSuccess() {
    try {
        def outDir = "${env.WORKSPACE}/${params.OUTPUT_SUBDIR}"
        def proj   = env.SLOC_PROJECT
                        ?: (params.SCAN_PATH?.trim()?.split('[/\\\\]') as List)?.last()
                        ?: 'project'
        def result = readJSON file: "${outDir}/result_${proj}.json"
        def t      = result.summary_totals

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
        def desc = "${fmtN(t.code_lines)} code · " +
                   "${fmtN(t.comment_lines)} cmts · " +
                   "${fmtN(t.blank_lines)} blank · " +
                   "${fmtN(t.files_analyzed)} files | ${params.SCAN_PATH}"

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
                desc += " · ${fmtN(passCount)}/${fmtN(totalTests)} tests ${testStatus}"
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
    if (env.BITBUCKET_SOURCE_BRANCH || env.GIT_COMMIT) {
        def state = currentBuild.result == 'SUCCESS' ? 'SUCCESSFUL' :
                    currentBuild.result == 'FAILURE'  ? 'FAILED' : 'STOPPED'
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

return this
