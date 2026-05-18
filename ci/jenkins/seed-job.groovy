// oxide-sloc — Jenkins Job DSL seed job
//
// Creates (or updates) the oxide-sloc pipeline job via the Job DSL plugin.
//
// Usage:
//   1. Install the "Job DSL" plugin.
//   2. Create a Freestyle project named "oxide-sloc-seed" (or similar).
//   3. Under Build Steps → Process Job DSLs, point it at this file
//      (using "Look on filesystem" or paste the content).
//   4. Run the seed job once — it creates the oxide-sloc pipeline job.
//   5. Run the generated job once with no parameters to seed the form;
//      the full "Build with Parameters" form appears from build #2 onward.
//
// Alternatively, paste this script directly into:
//   Manage Jenkins → Script Console (for one-shot execution without a seed job).
//
// Job name: defaults to 'oxide-sloc'. To override, set JOB_NAME before running:
//   - Job DSL seed job: add a String parameter named JOB_NAME to the seed job.
//   - Script Console: pass a binding variable, e.g. -DJOB_NAME=oxide-sloc-manual.
//   Use 'oxide-sloc-manual' if 'oxide-sloc' already exists in this Jenkins instance.
//
// Repo URL: defaults to the upstream GitHub repo. Override by setting REPO_URL:
//   - Job DSL seed job: add a String parameter named REPO_URL to the seed job.
//   - Script Console: set an env var or pass a binding variable.

def jobName = (binding.hasVariable('JOB_NAME') ? JOB_NAME : System.getenv('JOB_NAME')) ?: 'oxide-sloc'
def repoUrl = (binding.hasVariable('REPO_URL') ? REPO_URL : System.getenv('REPO_URL')) \
              ?: 'https://github.com/oxide-sloc/oxide-sloc.git'

pipelineJob(jobName) {
    description('''\
oxide-sloc — SLOC analysis pipeline.

Scans source repositories and produces HTML, JSON, CSV, XLSX, and PDF reports \
with build-over-build trend data (Plot plugin), JUnit test results (cargo-nextest), \
and code coverage (cargo-llvm-cov / cargo-tarpaulin).

Feature tiers — all configurable via "Build with Parameters":
  • 41-language SLOC analysis with 4 mixed-line policies and IEEE 1045-1992 options
  • HTML / PDF (pure-Rust) / CSV / XLSX report artifacts
  • JUnit test results: set TEST_RUNNER=cargo-nextest, PUBLISH_TEST_RESULTS=true
  • Code coverage: check COVERAGE_STANDALONE (requires cargo-llvm-cov or cargo-tarpaulin)
  • SLOC trend charts (Plot plugin): "SLOC Totals Over Time", "Per-Language Code Lines"
  • Coverage trend chart: "Line Coverage % Over Time" (when COVERAGE_STANDALONE enabled)
  • Artifact repository push: JFrog Artifactory, Nexus 3/2, S3, MinIO, Azure Blob, generic HTTP
  • Git-ref scan and diff comparison (GIT_REF / COMPARE_TO_REF)
  • Webhook and email delivery (WEBHOOK_URL / EMAIL_RECIPIENTS)
  • Pipeline-of-Pipelines chaining (DOWNSTREAM_JOB)

First build: run with no parameters to seed the "Build with Parameters" form.
Full setup guide: docs/jenkins-manual-setup.md''')

    logRotator {
        numToKeep(25)
        artifactNumToKeep(10)
    }

    // Prevent concurrent builds on the same agent.  The pipeline writes to a
    // fixed binary path (target/release/oxide-sloc) and extracts vendor.tar.xz
    // into a shared vendor/ directory — simultaneous builds would collide.
    properties {
        disableConcurrentBuilds()
    }

    definition {
        cpsScm {
            scm {
                git {
                    remote {
                        url(repoUrl)
                    }
                    branch('*/main')
                    extensions {
                        cloneOptions {
                            shallow(false)
                            timeout(10)
                        }
                        // Wipe the workspace before each checkout so stale vendor/
                        // directories from a crashed prior build cannot interfere.
                        wipeWorkspace()
                    }
                }

                // Bitbucket Server alternative — uncomment and set env vars to use:
                // bitbucketServer {
                //     serverUrl(System.getenv('BITBUCKET_URL') ?: 'https://bitbucket.example.com')
                //     credentialsId('bitbucket-credentials')
                //     projectKey(System.getenv('BITBUCKET_PROJECT') ?: 'OXIDE')
                //     repositoryName(System.getenv('BITBUCKET_REPO') ?: 'oxide-sloc')
                //     traits { ... }
                // }
            }
            scriptPath('Jenkinsfile')
            lightweight(true)
        }
    }
}
