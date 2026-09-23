// Declarative Jenkins Pipeline for the Go Snyk SBOM -> ServiceNow utility.
//
// Jenkins prerequisites:
//   * An agent with Go 1.22+ installed and network access to Snyk/ServiceNow.
//   * Credentials Binding plugin (for string credentials).
//   * Secret-text credentials containing the Snyk and ServiceNow tokens.

pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 90, unit: 'MINUTES')
    }

    parameters {
        choice(
            name: 'RUN_MODE',
            choices: ['SNYK_API', 'SNYK_CLI'],
            description: 'Generate SBOMs through the Snyk API or upload a file produced by the Snyk CLI.'
        )
        choice(
            name: 'SNOW_APPLICATION_SCOPE',
            choices: ['SNYK_PROJECT', 'SNYK_TARGET', 'SNYK_ORG'],
            description: 'Snyk processing scope (SNYK_API mode only).'
        )
        booleanParam(
            name: 'API_DRY_RUN',
            defaultValue: true,
            description: 'Generate and archive SBOMs without uploading them (SNYK_API mode only).'
        )
        string(
            name: 'SBOM_FILE_PATH',
            defaultValue: '',
            description: 'Workspace-relative SBOM file path (required in SNYK_CLI mode).',
            trim: true
        )

        string(name: 'SNYK_ORG_ID', defaultValue: '', description: 'Snyk Organization ID.', trim: true)
        string(name: 'SNYK_TARGET_ID', defaultValue: '', description: 'Snyk Target ID (project/target scopes).', trim: true)
        string(name: 'SNYK_PROJECT_ID', defaultValue: '', description: 'Snyk Project ID (project scope).', trim: true)
        string(name: 'SNYK_BASE_URL', defaultValue: 'https://api.snyk.io/rest', description: 'Snyk REST API base URL.', trim: true)
        string(name: 'SNYK_REST_API_VERSION', defaultValue: '2026-03-25', description: 'Snyk REST API version.', trim: true)
        string(name: 'SNYK_SBOM_FORMAT', defaultValue: 'cyclonedx1.6+json', description: 'Snyk SBOM format.', trim: true)

        string(name: 'SNOW_INSTANCE_SUBDOMAIN', defaultValue: '', description: 'ServiceNow instance subdomain.', trim: true)
        string(name: 'SNOW_BUSINESS_APPLICATION_ID', defaultValue: '', description: 'ServiceNow Business Application ID.', trim: true)

        choice(name: 'DEBUG_LEVEL', choices: ['INFO', 'WARNING', 'ERROR', 'DEBUG', 'TRACE'], description: 'Application log level.')
        string(name: 'HTTP_TIMEOUT_SECONDS', defaultValue: '60', description: 'Per-request HTTP timeout.', trim: true)
        booleanParam(name: 'SSL_VERIFY', defaultValue: true, description: 'Verify TLS certificates.')
        string(name: 'CA_BUNDLE', defaultValue: '', description: 'Optional workspace/agent path to a PEM CA bundle.', trim: true)
        string(name: 'VERSION', defaultValue: '1.0.0', description: 'Semantic version embedded in the binary.', trim: true)
    }

    environment {
        GO_MODULE_DIR = 'go'
        APP_NAME = 'snyk-sbom-to-servicenow'
        // Update these two IDs to match Secret Text credentials in Jenkins.
        SNYK_TOKEN_CREDENTIAL_ID = 'snyk-api-token'
        SNOW_TOKEN_CREDENTIAL_ID = 'servicenow-access-token'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Validate Parameters') {
            steps {
                script {
                    def requireValue = { value, name ->
                        if (value == null || value.toString().trim().isEmpty()) {
                            error("${name} is required for the selected RUN_MODE/scope.")
                        }
                    }

                    requireValue(params.SNOW_INSTANCE_SUBDOMAIN, 'SNOW_INSTANCE_SUBDOMAIN')
                    requireValue(params.SNOW_BUSINESS_APPLICATION_ID, 'SNOW_BUSINESS_APPLICATION_ID')
                    if (!(params.SNOW_INSTANCE_SUBDOMAIN ==~ /^[A-Za-z0-9-]+$/)) {
                        error('SNOW_INSTANCE_SUBDOMAIN may contain only letters, digits, and hyphens.')
                    }

                    if (params.RUN_MODE == 'SNYK_CLI') {
                        requireValue(params.SBOM_FILE_PATH, 'SBOM_FILE_PATH')
                        if (!fileExists(params.SBOM_FILE_PATH)) {
                            error("SBOM_FILE_PATH does not exist in the Jenkins workspace: ${params.SBOM_FILE_PATH}")
                        }
                    } else {
                        requireValue(params.SNYK_ORG_ID, 'SNYK_ORG_ID')
                        if (!(params.SNYK_BASE_URL ==~ /^https:\/\/([A-Za-z0-9-]+\.)*snyk\.io\/rest\/?$/)) {
                            error('SNYK_BASE_URL must be an HTTPS snyk.io REST API URL.')
                        }

                        if (params.SNOW_APPLICATION_SCOPE in ['SNYK_PROJECT', 'SNYK_TARGET']) {
                            requireValue(params.SNYK_TARGET_ID, 'SNYK_TARGET_ID')
                        }
                        if (params.SNOW_APPLICATION_SCOPE == 'SNYK_PROJECT') {
                            requireValue(params.SNYK_PROJECT_ID, 'SNYK_PROJECT_ID')
                        }
                    }
                }
            }
        }

        stage('Test and Build') {
            steps {
                sh '''
                    set -eu
                    command -v go >/dev/null 2>&1 || {
                      echo "Go is not installed on this Jenkins agent (Go 1.22+ required)." >&2
                      exit 1
                    }

                    cd "$GO_MODULE_DIR"
                    go version
                    test -z "$(gofmt -l ./cmd ./internal)"
                    go vet ./...
                    go test ./...

                    mkdir -p bin
                    CGO_ENABLED=0 go build \
                      -trimpath \
                      -ldflags "-s -w -X main.version=$VERSION" \
                      -o "bin/$APP_NAME" \
                      "./cmd/$APP_NAME"

                    "./bin/$APP_NAME" --version
                '''
            }
        }

        stage('Run') {
            steps {
                script {
                    def commonEnvironment = [
                        "RUN_MODE=${params.RUN_MODE}",
                        "SNOW_APPLICATION_SCOPE=${params.SNOW_APPLICATION_SCOPE}",
                        "API_DRY_RUN=${params.API_DRY_RUN}",
                        "SNYK_ORG_ID=${params.SNYK_ORG_ID}",
                        "SNYK_TARGET_ID=${params.SNYK_TARGET_ID}",
                        "SNYK_PROJECT_ID=${params.SNYK_PROJECT_ID}",
                        "SNYK_BASE_URL=${params.SNYK_BASE_URL}",
                        "SNYK_REST_API_VERSION=${params.SNYK_REST_API_VERSION}",
                        "SNYK_SBOM_FORMAT=${params.SNYK_SBOM_FORMAT}",
                        "SNOW_INSTANCE_SUBDOMAIN=${params.SNOW_INSTANCE_SUBDOMAIN}",
                        "SNOW_BUSINESS_APPLICATION_ID=${params.SNOW_BUSINESS_APPLICATION_ID}",
                        "DEBUG_LEVEL=${params.DEBUG_LEVEL}",
                        "HTTP_TIMEOUT_SECONDS=${params.HTTP_TIMEOUT_SECONDS}",
                        "SSL_VERIFY=${params.SSL_VERIFY}",
                        "CA_BUNDLE=${params.CA_BUNDLE}"
                    ]

                    def snowCredential = string(
                        credentialsId: env.SNOW_TOKEN_CREDENTIAL_ID,
                        variable: 'SNOW_ACCESS_TOKEN'
                    )

                    if (params.RUN_MODE == 'SNYK_CLI') {
                        withEnv(commonEnvironment + ["SBOM_FILE_PATH=${params.SBOM_FILE_PATH}"]) {
                            withCredentials([snowCredential]) {
                                sh '''
                                    set -eu
                                    set +x
                                    "./$GO_MODULE_DIR/bin/$APP_NAME" \
                                      --sbom-file-path "$SBOM_FILE_PATH"
                                '''
                            }
                        }
                    } else {
                        def snykCredential = string(
                            credentialsId: env.SNYK_TOKEN_CREDENTIAL_ID,
                            variable: 'SNYK_API_TOKEN'
                        )
                        withEnv(commonEnvironment) {
                            withCredentials([snowCredential, snykCredential]) {
                                sh '''
                                    set -eu
                                    set +x
                                    "./$GO_MODULE_DIR/bin/$APP_NAME"
                                '''
                            }
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts(
                artifacts: 'go/bin/snyk-sbom-to-servicenow,*-snyk-*-sbom.json',
                allowEmptyArchive: true,
                fingerprint: true
            )
        }
        cleanup {
            deleteDir()
        }
    }
}
