# Snyk SBOM → ServiceNow Upload Utility

**Version:** 1.0.0

A lightweight, environment-variable-driven Python utility that exports a
Software Bill of Materials (SBOM) from Snyk and uploads it to **ServiceNow
Vulnerability Response**. It can process a single Snyk project, every project in
a target, or an entire organization — or upload an SBOM file you already
produced with the Snyk CLI.

It requires **no code changes** for normal operation, is driven entirely by
environment variables, and provides verbose, variable-level debug logging with
automatic redaction of secrets.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Running the distributable](#running-the-distributable)
- [Run modes (`RUN_MODE`)](#run-modes-run_mode)
- [Generating an SBOM with the Snyk CLI (SNYK_CLI mode)](#generating-an-sbom-with-the-snyk-cli-snyk_cli-mode)
- [Processing scope (`SNOW_APPLICATION_SCOPE`)](#processing-scope-snow_application_scope)
- [Configuration reference](#configuration-reference)
- [SBOM file output](#sbom-file-output)
- [ServiceNow endpoint](#servicenow-endpoint)
- [Usage examples](#usage-examples)
- [Exit codes](#exit-codes)
- [Logging & secret redaction](#logging--secret-redaction)
- [TLS / certificates](#tls--certificates)
- [Troubleshooting](#troubleshooting)
- [Distribution & layout](#distribution--layout)
- [Versioning](#versioning)

---

## Features

- **Two run modes:** call the Snyk REST API (`SNYK_API`) or upload a Snyk-CLI
  produced SBOM file (`SNYK_CLI`).
- **Configurable scope:** one project, all projects in a target, or all projects
  across an organization — one ServiceNow Business Application per run.
- **Resilient batch processing:** per-project failures are isolated and
  summarized; project types that don't support SBOM export are **skipped**, not
  failed.
- **Auditable output:** every generated SBOM is written to a timestamped
  `.json` file, and that exact file is uploaded.
- **Safe logging:** leveled logging (`ERROR`…`TRACE`) with automatic masking of
  tokens, passwords, and `Authorization` headers.
- **Enterprise-friendly TLS:** verifies against the OS trust store (like
  `curl`), with a `CA_BUNDLE` override for corporate proxies.
- **Deterministic exit codes** for clean CI/automation integration.
- **Single-file distribution** (`snyk_sbom_to_servicenow.py`) for easy delivery.

## How it works

```
                 ┌──────────────────────────── RUN_MODE ────────────────────────────┐
                 │                                                                   │
            SNYK_API                                                            SNYK_CLI
                 │                                                                   │
   Validate config + Snyk/ServiceNow vars                       Validate config + --sbom-file-path
                 │                                                                   │
   Discover projects for scope                                   (file already produced by Snyk CLI)
   (project / target / org)                                                          │
                 │                                                                   │
   For each project:                                                                 │
     • Generate SBOM (Snyk REST API)                                                 │
     • Write timestamped .json file                                                  │
     • Upload file to ServiceNow  ───────────────┐                 Upload file to ServiceNow
                 │                                │                                   │
   Print processing summary + exit code ◄─────────┴───────────────────────────────► exit code
```

## Requirements

- **Python 3.12+**
- Python packages (see `requirements.txt`):
  - `requests` — HTTP client
  - `python-dotenv` — `.env` loading
  - `truststore` — OS trust store for TLS verification (recommended)

## Install

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Quick start

1. Copy the example environment file and fill in your values:

   ```bash
   cp .env.example .env
   ```

2. Run it (defaults to `SNYK_API` mode, `SNYK_PROJECT` scope):

   ```bash
   python snyk_sbom_to_servicenow.py
   ```

Check the version at any time:

```bash
python snyk_sbom_to_servicenow.py --version
```

> The examples below use the single-file distribution
> `snyk_sbom_to_servicenow.py`. The development package exposes the same
> behavior via `python main.py` — the commands are interchangeable.

---

## Running the distributable

The deliverable is a single, readable Python file: **`snyk_sbom_to_servicenow.py`**.
It carries [PEP 723](https://peps.python.org/pep-0723/) inline metadata declaring
its pinned dependencies, so there are three supported ways to run it. Pick the
one that fits your environment.

| Option | Prerequisite | Installs deps? | Best for |
| --- | --- | --- | --- |
| A. `uv run` | [`uv`](https://docs.astral.sh/uv/) | Automatic (cached, ephemeral) | Zero-setup; the simplest one-liner |
| B. `pipx run` | [`pipx`](https://pipx.pypa.io/) | Automatic (cached, ephemeral) | Teams already standardized on pipx |
| C. Plain `python` + venv | Python 3.12+ | Manual (`pip install`) | Air-gapped/regulated hosts, full control/auditability |

In every option, the tool reads its configuration from the environment and a
`.env` file in the **current working directory**, and (in `SNYK_API` mode)
writes SBOM files to that directory — so run it from the folder that holds your
`.env`.

### Option A — `uv run` (zero-install, recommended)

`uv` reads the inline dependency block, provisions a cached environment with the
exact pinned versions, and runs the file. No virtualenv or `pip install` needed.

```bash
# one-time: install uv (https://docs.astral.sh/uv/getting-started/installation/)
uv run snyk_sbom_to_servicenow.py                 # SNYK_API mode (uses .env)
uv run snyk_sbom_to_servicenow.py --version
RUN_MODE=SNYK_CLI uv run snyk_sbom_to_servicenow.py --sbom-file-path ./sbom.json
```

### Option B — `pipx run`

```bash
pipx run snyk_sbom_to_servicenow.py               # SNYK_API mode (uses .env)
pipx run snyk_sbom_to_servicenow.py --version
```

### Option C — Plain Python + a virtual environment

Install the pinned dependencies once, then run with the stock interpreter. The
PEP 723 header is just a comment to plain Python, so this works unchanged.

```bash
python -m venv .venv
source .venv/bin/activate                         # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python snyk_sbom_to_servicenow.py                 # SNYK_API mode (uses .env)
RUN_MODE=SNYK_CLI python snyk_sbom_to_servicenow.py --sbom-file-path ./sbom.json
```

For a fully offline host, pre-download the wheels on a connected machine and
install from that folder:

```bash
# connected machine
pip download -r requirements.txt -d wheels/
# air-gapped host
pip install --no-index --find-links wheels/ -r requirements.txt
python snyk_sbom_to_servicenow.py
```

### Optional — run it as an executable

Because the file has a `#!/usr/bin/env python3` shebang, you can mark it
executable and invoke it directly (dependencies must already be importable, i.e.
Option C):

```bash
chmod +x snyk_sbom_to_servicenow.py
./snyk_sbom_to_servicenow.py --version
```

> **Interpreter note:** all three options require Python **3.12+** to be
> available (or, for A/B, `uv`/`pipx`, which manage a compatible interpreter).
> The single file bundles no interpreter — if the target has no Python at all,
> package a native executable instead (e.g. with PyInstaller or Nuitka).

---

## Run modes (`RUN_MODE`)

`RUN_MODE` (default `SNYK_API`) selects how the SBOM is obtained. An unrecognized
value fails fast with a configuration error (exit `1`).

| `RUN_MODE` value | Behavior | Required inputs |
| --- | --- | --- |
| `SNYK_API` (default) | Call the Snyk API to generate SBOM(s) per `SNOW_APPLICATION_SCOPE`, then upload each to ServiceNow | Snyk API vars + scope vars + ServiceNow vars |
| `SNYK_CLI` | Upload an SBOM file you produced with the Snyk CLI | ServiceNow vars + `--sbom-file-path` |

**`SNYK_CLI` mode** — you run the Snyk CLI yourself (e.g. `snyk sbom --format=cyclonedx1.6+json > sbom.json`)
and hand the file to the utility. Only the ServiceNow variables are required (no
Snyk API token/org/scope):

```bash
RUN_MODE=SNYK_CLI python snyk_sbom_to_servicenow.py --sbom-file-path ./sbom.json
```

The file path is validated (exists, is a file, readable, non-empty) **before**
any network call. The upload is tagged `sbomSource=SnykCLI` (vs. `sbomSource=SnykAPI`
in API mode). `API_DRY_RUN` has no effect in CLI mode.

## Generating an SBOM with the Snyk CLI (SNYK_CLI mode)

In `SNYK_CLI` mode this utility does **not** call the Snyk API — it simply
uploads an SBOM file that you generate yourself with the native
[`snyk sbom`](https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/commands/sbom)
command. This is useful for local/offline scans, monorepos, or CI pipelines
where the Snyk CLI already runs.

**Prerequisites** (per the [Snyk CLI SBOM docs](https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/commands/sbom)):

- The `snyk sbom` command requires a **Snyk Enterprise plan** and **Snyk CLI ≥ 1.1071.0**.
- The Snyk CLI needs its own authentication (`snyk auth`) — this is separate
  from and independent of this utility's configuration. In `SNYK_CLI` mode the
  utility itself needs only the ServiceNow variables.
- Produce a **JSON** SBOM (a `+json` format). The upload is sent with
  `Content-Type: application/json`, so JSON — e.g. `cyclonedx1.6+json` (matching
  API mode) or `spdx2.3+json` — is required; XML formats are not appropriate here.

### Step 1 — generate the SBOM file with the Snyk CLI

The `snyk sbom` command writes the document to **stdout**, so redirect it to a
file (or use `--json-file-output`). Run this in your project directory:

```bash
# Redirect stdout to a file
snyk sbom --format=cyclonedx1.6+json > sbom.json

# ...or write directly to a file (requires a +json format)
snyk sbom --format=cyclonedx1.6+json --json-file-output=sbom.json

# Monorepo: detect all projects and emit a single combined SBOM
snyk sbom --format=cyclonedx1.6+json --all-projects > sbom.json

# Optionally scope to a specific Snyk Organization
snyk sbom --format=cyclonedx1.6+json --org=<ORG_ID> > sbom.json
```

`snyk sbom` exits `0` on success and `2` on failure (re-run with `-d` for debug
logs). See the full option list in the
[Snyk CLI SBOM documentation](https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/commands/sbom).

### Step 2 — upload that file with this utility

Point the utility at the file the Snyk CLI produced. Only the ServiceNow
variables need to be set (in `.env` or the environment):

```bash
RUN_MODE=SNYK_CLI python snyk_sbom_to_servicenow.py --sbom-file-path ./sbom.json
```

Or as a single pipeline that generates then uploads:

```bash
snyk sbom --format=cyclonedx1.6+json --all-projects > sbom.json \
  && RUN_MODE=SNYK_CLI python snyk_sbom_to_servicenow.py --sbom-file-path ./sbom.json
```

The utility validates the file, then `POST`s its exact bytes to
`https://<SNOW_INSTANCE_SUBDOMAIN>.service-now.com/api/sbom/core/upload?businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>&sbomSource=SnykCLI`.
On success it exits `0`; a missing/empty/unreadable path exits `1` (before any
network call), an auth failure exits `2`, and an upload failure exits `4`.

## Processing scope (`SNOW_APPLICATION_SCOPE`)

In `SNYK_API` mode, `SNOW_APPLICATION_SCOPE` (default `SNYK_PROJECT`) controls
how many Snyk projects a single run uploads to the one ServiceNow Business
Application. The Snyk identifiers you must set depend on the scope:

| `SNOW_APPLICATION_SCOPE` value | Required Snyk vars | Behavior |
| --- | --- | --- |
| `SNYK_PROJECT` (default) | `SNYK_ORG_ID`, `SNYK_TARGET_ID`, `SNYK_PROJECT_ID` | One SBOM for the given project |
| `SNYK_TARGET` | `SNYK_ORG_ID`, `SNYK_TARGET_ID` | One SBOM per project in the target |
| `SNYK_ORG` | `SNYK_ORG_ID` | One SBOM per project across all targets in the org |

An unrecognized value fails fast with a configuration error (exit `1`).

**Failure handling.** Per-project failures are logged and do **not** stop the
run. Projects whose type does not support SBOM export (Snyk returns HTTP 404 —
e.g. SAST, IaC, and container projects) are reported as **Skipped
(unsupported)**, *not* failures, so they don't count toward the exit code. The
process exits `4` only if a project genuinely failed, and `0` when every project
succeeded or was skipped.

At the end of an API-mode run, a summary is printed, e.g.:

```
Processing summary:
  Scope: SNYK_ORG
  Targets discovered: 11
  Projects discovered: 77
  SBOMs generated: 22
  Successful uploads: 22
  Skipped (unsupported): 55
  Failed: 0
  Elapsed time: 42s
```

## Configuration reference

Configuration is read from the process environment, with a local `.env` file
loaded as a fallback (process environment wins). Copy `.env.example` to `.env`
as a starting point. Placeholder values (those starting with `MY_`) are rejected
with a clear error so an unfilled `.env` fails fast.

### Required variables

Always required (every run mode):

| Variable | Description |
| --- | --- |
| `SNOW_INSTANCE_SUBDOMAIN` | ServiceNow instance subdomain (`<subdomain>.service-now.com`) |
| `SNOW_ACCESS_TOKEN` | ServiceNow bearer access token |
| `SNOW_BUSINESS_APPLICATION_ID` | Target ServiceNow business application id |

Additionally required in **`SNYK_API`** mode (per the scope table above):

| Variable | Description |
| --- | --- |
| `SNYK_API_TOKEN` | Snyk REST API token |
| `SNYK_ORG_ID` | Snyk organization ID |
| `SNYK_TARGET_ID` | Snyk target ID (required for `SNYK_PROJECT` / `SNYK_TARGET` scope) |
| `SNYK_PROJECT_ID` | Snyk project ID (required for `SNYK_PROJECT` scope) |

In **`SNYK_CLI`** mode the Snyk API variables are not required; provide
`--sbom-file-path` on the command line instead.

### Optional variables (defaults shown)

| Variable | Default | Description |
| --- | --- | --- |
| `RUN_MODE` | `SNYK_API` | `SNYK_API` \| `SNYK_CLI` |
| `SNOW_APPLICATION_SCOPE` | `SNYK_PROJECT` | `SNYK_PROJECT` \| `SNYK_TARGET` \| `SNYK_ORG` (API mode only) |
| `SNYK_BASE_URL` | `https://api.snyk.io/rest` | Snyk REST API base URL (override for non-default regions/tenants) |
| `SNYK_REST_API_VERSION` | _(none)_ | Snyk REST API version query parameter |
| `SNYK_SBOM_FORMAT` | `cyclonedx1.6+json` | Any Snyk-supported SBOM format (e.g. `spdx2.3+json`) |
| `DEBUG_LEVEL` | `INFO` | `ERROR` \| `WARNING` \| `INFO` \| `DEBUG` \| `TRACE` |
| `API_DRY_RUN` | `false` | (API mode only) Generate + persist the SBOM but skip the ServiceNow upload |
| `HTTP_TIMEOUT_SECONDS` | `60` | Per-request HTTP timeout (seconds) |
| `SSL_VERIFY` | `true` | Verify TLS certificates (uses the OS trust store, like `curl`) |
| `CA_BUNDLE` | _(none)_ | Path to a PEM CA bundle to use instead of the OS trust store |

`SNYK_PLATFORM_DOMAIN` may appear in `.env` for reference but is informational
only (not used for API calls).

## SBOM file output

Every generated SBOM is written to a timestamped file in the **current working
directory**, named:

```
<timestamp>-snyk-<project_id>-sbom.json
# e.g. 20260716T191500Z-snyk-08310a59-5877-4030-a492-116cb83bdc2e-sbom.json
```

The timestamp is UTC in `YYYYMMDDTHHMMSSZ` form (filename-safe and sortable).
That exact file is what gets uploaded to ServiceNow (equivalent to
`curl --data-binary @<file>`). Files are **not** auto-pruned and are git-ignored
via the `*-snyk-*-sbom.json` pattern. Run from the directory where you want the
files written.

> In `SNYK_CLI` mode no new file is written — the file you pass via
> `--sbom-file-path` is uploaded as-is.

## ServiceNow endpoint

The SBOM is uploaded with an HTTP `POST`:

```
POST https://<SNOW_INSTANCE_SUBDOMAIN>.service-now.com/api/sbom/core/upload?businessApplicationId=<SNOW_BUSINESS_APPLICATION_ID>&sbomSource=<SnykAPI|SnykCLI>
Authorization: Bearer <SNOW_ACCESS_TOKEN>
Content-Type: application/json

<raw SBOM file bytes>
```

`sbomSource` is `SnykAPI` in API mode and `SnykCLI` in CLI mode so ServiceNow
can distinguish the origin.

## Usage examples

Run from the directory where you want SBOM files written.

```bash
# API mode, single project (uses .env)
python snyk_sbom_to_servicenow.py

# API mode, every project in a target
SNOW_APPLICATION_SCOPE=SNYK_TARGET python snyk_sbom_to_servicenow.py

# API mode, every project in the organization
SNOW_APPLICATION_SCOPE=SNYK_ORG python snyk_sbom_to_servicenow.py

# API mode dry run: generate + persist SBOM(s), skip the ServiceNow upload
API_DRY_RUN=true python snyk_sbom_to_servicenow.py

# CLI mode: upload an SBOM file produced by the Snyk CLI (no Snyk API calls)
RUN_MODE=SNYK_CLI python snyk_sbom_to_servicenow.py --sbom-file-path ./sbom.json

# Verbose troubleshooting (secrets are always redacted)
DEBUG_LEVEL=TRACE python snyk_sbom_to_servicenow.py

# Show the version
python snyk_sbom_to_servicenow.py --version
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (all projects uploaded, or all succeeded/skipped) |
| 1 | Configuration error (missing/invalid variables, invalid `--sbom-file-path`) |
| 2 | Authentication failure (Snyk or ServiceNow) |
| 3 | SBOM generation failure (single-project run) |
| 4 | ServiceNow upload failure / one or more projects failed |
| 5 | Unexpected exception |

## Logging & secret redaction

Set `DEBUG_LEVEL` to control verbosity: `ERROR`, `WARNING`, `INFO` (default),
`DEBUG`, or `TRACE`. At `DEBUG`/`TRACE` the utility logs named variables,
request/response metadata, and timing. `TRACE` additionally logs request/response
bodies and full headers.

Sensitive values — tokens, passwords, and `Authorization` headers — are
**always masked**, at every level, so logs are safe to share. For example, an
`Authorization: Bearer <token>` header is logged as `Bearer ************`.

## TLS / certificates

Certificates are verified against the **operating system trust store** (via the
`truststore` package), matching `curl`. This avoids `certifi`
"unable to get local issuer certificate" errors for hosts whose chain the OS can
verify but the bundled CA set cannot (common with corporate TLS proxies or
servers that omit intermediate certificates).

- Set `CA_BUNDLE=/path/to/ca-bundle.pem` to verify against a specific PEM bundle
  (e.g. your organization's root CA).
- Set `SSL_VERIFY=false` to disable verification entirely (**not recommended**).

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `Configuration still contains placeholder value(s): ...` | Your `.env` still has `MY_...` placeholders, or edits weren't **saved** to disk. Fill in real values and save. |
| `Missing required configuration variable(s) ...` | A variable required for the selected `RUN_MODE`/scope is unset. See the tables above. |
| `Invalid RUN_MODE` / `Invalid SNOW_APPLICATION_SCOPE` | Value must be one of the accepted values (case-insensitive). |
| `SSL: CERTIFICATE_VERIFY_FAILED` | TLS trust issue. Ensure `truststore` is installed, or set `CA_BUNDLE` to your corporate CA bundle. |
| Many projects `Skipped (unsupported)` in `SNYK_ORG` scope | Expected — Snyk only produces SBOMs for SCA/open-source project types; SAST/IaC/container projects return 404 and are skipped. |
| `401` / `403` from ServiceNow | `SNOW_ACCESS_TOKEN` is invalid/expired or lacks SBOM upload permission. |
| `401` / `403` from Snyk | `SNYK_API_TOKEN` is invalid or can't access `SNYK_ORG_ID`. |

## Distribution & layout

There are two equivalent ways to run the tool:

- **Single-file distribution (recommended for delivery):**
  `snyk_sbom_to_servicenow.py` — the entire application combined into one file
  with no internal imports. Ship this file plus `requirements.txt` and
  `.env.example`.

  ```bash
  python snyk_sbom_to_servicenow.py [--sbom-file-path <file>] [--version]
  ```

- **Development package:** the same logic organized into modules for
  maintainability:

  ```
  main.py                     # entrypoint + argparse + exit-code mapping
  app/
  ├── config.py               # .env loading, validation, defaults, RUN_MODE/scope
  ├── logging.py              # leveled logging (ERROR..TRACE)
  ├── errors.py               # exception hierarchy + exit codes
  ├── tls.py                  # OS trust store (truststore) integration
  ├── snyk_client.py          # Snyk SBOM generation
  ├── project_discovery.py    # enumerate Snyk targets/projects (paginated)
  ├── sbom_file.py            # timestamped SBOM file persistence
  ├── servicenow_client.py    # ServiceNow SBOM upload
  ├── sbom_service.py         # single-project: generate -> persist -> upload
  ├── scope_manager.py        # orchestrate discovery + per-project processing
  ├── cli_mode.py             # SNYK_CLI: validate + upload a provided file
  └── utils/
      ├── debug.py            # variable logging + secret redaction
      ├── http.py             # HTTP wrapper (timeout, timing, logging, errors)
      └── validators.py       # config/response validation helpers
  ```

> Note: in the development package the modules live under `app/` (rather than
> flat at the repo root) so that `logging.py` does not shadow Python's
> standard-library `logging` module. The single-file build avoids the issue
> entirely by using the stdlib logger directly.

### Rebuilding the single file

The `app/` package is the source of truth; `snyk_sbom_to_servicenow.py` is a
**generated** artifact. After changing anything under `app/` (or `main.py`),
regenerate the single file with the bundled builder:

```bash
python build_single_file.py            # regenerate snyk_sbom_to_servicenow.py
python build_single_file.py --check    # CI: fail if the committed file is stale
```

The builder flattens the modules in dependency order, hoists/de-duplicates
imports, rewrites intra-package calls to their flattened names, and prepends the
shebang, PEP 723 dependency metadata (read from `requirements.txt`), and
`__version__` (read from `app/__init__.py`). Do not edit
`snyk_sbom_to_servicenow.py` by hand — your changes would be overwritten on the
next build.

## Versioning

This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
The current version is **1.0.0** and is reported by:

```bash
python snyk_sbom_to_servicenow.py --version
```

Notable considerations for upgrades:

- **1.0.0** — first customer release. Consolidates the Snyk→ServiceNow SBOM
  workflow: `SNYK_API`/`SNYK_CLI` run modes, project/target/org scope,
  unsupported-project skipping, OS-trust-store TLS, timestamped SBOM files, and
  mode-tagged `sbomSource`. (Note: the ServiceNow `sbomSource` value is
  `SnykAPI`/`SnykCLI`; the configuration variable for the target application is
  `SNOW_BUSINESS_APPLICATION_ID` and the dry-run flag is `API_DRY_RUN`.)
