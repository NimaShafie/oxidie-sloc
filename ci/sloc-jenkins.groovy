// oxide-sloc Jenkins shared library step
//
// Place this file at vars/slocAnalyze.groovy in your Jenkins shared library,
// then call it from any Jenkinsfile after 'cargo install oxide-sloc' is on PATH.
//
// Usage:
//   @Library('your-shared-lib') _
//   pipeline {
//     agent any
//     stages {
//       stage('SLOC') {
//         steps { slocAnalyze(label: env.JOB_NAME) }
//       }
//     }
//   }
//
// Required:  SLOC_SERVER env var or `server` argument (base URL of oxide-sloc instance)
// Optional:  SLOC_API_KEY env var or `apiKey` argument (bearer token for auth)
//
// How it works:
//   1. oxide-sloc analyze runs on the Jenkins agent — no network call to the server.
//   2. oxide-sloc send POSTs the result JSON to /api/ingest on your server.
//   3. The server renders HTML, stores the artifact, and the scan appears in /view-reports.

def call(Map args = [:]) {
    def server = args.server ?: env.SLOC_SERVER
    if (!server) {
        error('slocAnalyze: set the SLOC_SERVER environment variable or pass server: "http://..." as an argument')
    }

    def label    = args.label  ?: (env.JOB_NAME ?: 'jenkins-build')
    def apiKey   = args.apiKey ?: (env.SLOC_API_KEY ?: '')
    def scanPath = args.path   ?: '.'
    def jsonOut  = args.output ?: 'sloc-result.json'

    def encodedLabel = URLEncoder.encode(label as String, 'UTF-8')
    def tokenFlag = apiKey ? "--webhook-token '${apiKey}'" : ''

    sh """
        oxide-sloc analyze '${scanPath}' --json-out '${jsonOut}'
        oxide-sloc send '${jsonOut}' \\
            --webhook-url '${server}/api/ingest?label=${encodedLabel}' \\
            ${tokenFlag}
    """

    archiveArtifacts artifacts: jsonOut, allowEmptyArchive: true
}
