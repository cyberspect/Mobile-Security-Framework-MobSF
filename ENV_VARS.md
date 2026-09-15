# Environment Variables Reference

| Env Var | Origin found in code | Loaded from | Role |
|---|---|---|---|
| `ADMIN_GROUP` | `settings.py:607` → `settings.ADMIN_GROUP` in `cyberspect_utils.py`/`cyberspect/utils.py` | `cyberspect.env` (mobsf/qcluster `env_file`) | Group name assigned to admin users via `get_usergroups()`; used for SSO/group-based authorization display. |
| `ADMIN_USERS` | `settings.py:602,605` → `is_admin()` | `cyberspect.env` | Comma-separated email allowlist gating the Admin screen and all admin key-management actions. |
| `AWS_REGION` | `settings.py:601`; `aws_sso_middleware.py:22-27` | `cyberspect.env` (also set explicitly in AWS ECS task definitions/CI for deployed environments) | Required by the SSO middleware for AWS calls (e.g. Cognito/JWT verification); raises if unset. |
| `AWS_ACCESS_KEY_ID` | Not referenced directly in MobSF/Cyberspect app code — appears only in AWS deploy configs (ECS task defs, GitHub Actions secrets) | `cyberspect.env`/`qcluster.env` locally (if boto3 calls are made), or ECS task definitions / GitHub Actions secrets in deployed environments | Standard AWS SDK credential, picked up implicitly by boto3 for AWS API calls (e.g. from Lambda/CI), not read explicitly by MobSF's Python code. |
| `CYBERSPECT_ENVIRONMENT` | Not in MobSF — only in `cyberspect-automated-tests/config.py:14` | `cyberspect-automated-tests/.env` or shell `export` | Test-project setting: selects `local` vs `qa` target server/base URL. |
| `CYBERSPECT_LOCAL_AUTH_TOKEN` | `cyberspect-automated-tests/config.py:24` | `cyberspect-automated-tests/.env` or shell `export` | Test-project auth token sent as `Authorization` header when targeting local. |
| `CZ100` | `settings.py:615`; `api_middleware.py:120-121` | `cyberspect.env` | Hostname value; if set, restricts non-`/api/` (and select `/api/`) endpoints to requests whose `HTTP_HOST` matches it. |
| `DEPENDENCY_TRACK_URL` | `settings.py:604`; `views/home.py:432` | `cyberspect.env` | URL of the Dependency-Track instance, exposed to templates for linking out to SCA results. |
| `EFR_01` | `settings.py:425`; `appsec.py:154,164,186,400` | `cyberspect.env` | Feature flag altering vulnerability severity labeling (`hotspot` vs `high`/`warning`) in the appsec scoring logic. |
| `FILES_PATH` | `init.py:128` | `cyberspect.env`/`qcluster.env` (falls back to `os.path.expanduser('~')` if unset) | Overrides the default MobSF files/downloads directory path. |
| `GENERAL_GROUP` | `settings.py:606`; `cyberspect_utils.py`/`cyberspect/utils.py` | `cyberspect.env` | Group name for non-admin users, counterpart to `ADMIN_GROUP`. |
| `MOBSF_ASYNC_ANALYSIS` | `settings.py:393`; `docker/docker-compose.yml:75` | `cyberspect.env` locally; hardcoded `=1` in `docker/docker-compose.yml` for that compose setup | Enables async scan mode (`ASYNC_ANALYSIS`), required for the async/queued scan API endpoints (django-q). |
| `MOBSF_DEBUG` | `Dockerfile.dev:21`; `settings.py:182` | Image `ENV` default in `Dockerfile.dev` (`=0`); overridable via `cyberspect.env` | Django `DEBUG` flag. |
| `MOBSF_DISABLE_AUTHENTICATION` | `Dockerfile.dev:22`; `settings.py:414`; CI workflow | Image `ENV` default in `Dockerfile.dev` (`=1`); overridable via `cyberspect.env`; hardcoded `"1"` in `.github/workflows/mobsf-test.yml` for CI | Toggles whether login/auth is enforced at all. |
| `MOBSF_JADX_BINARY` | `settings.py:511,624` | `cyberspect.env`/`qcluster.env` (optional; defaults to `''`) | Path override for the `jadx` decompiler binary used in static analysis. |
| `MOBSF_MULTIPROCESSING` | `settings.py:409` | `cyberspect.env` | Controls multiprocessing behavior during analysis. |
| `MOBSF_URL` | Not in MobSF/Cyberspect app itself — used throughout the AWS Lambda functions (`aws/lambda/*/lambda_function.py`, `lambda function code/*.py`) | Lambda function environment configuration (set on the Lambda resource itself, e.g. via Terraform/console/ECS — not `cyberspect.env`) | Base URL the Lambda functions (intake, notify, monthly-scan, cleanup, released-apps-notify) use to call the MobSF REST API — not something MobSF reads about itself. |
| `MOBSF_VT_ENABLED` | `settings.py:567` | `cyberspect.env` | Enables VirusTotal integration. |
| `MOBSF_VT_UPLOAD` | `settings.py:569` | `cyberspect.env` | Enables uploading samples to VirusTotal (vs. hash-only lookups). |
| `POSTGRES_USER` | `settings.py:158,166`; all compose files | `docker-compose-dev.yml` (hardcoded `postgres` for the `postgres` service); must independently match in `cyberspect.env`/`qcluster.env` for the `mobsf`/`qcluster` services | DB connection credential — required for MobSF to use Postgres. |
| `POSTGRES_PASSWORD` | `settings.py:159-160,167` (or `POSTGRES_PASSWORD_FILE`) | `docker-compose-dev.yml` (hardcoded `password` for `postgres` service); must match in `cyberspect.env`/`qcluster.env` | DB connection credential. |
| `POSTGRES_DB` | `settings.py:165` | `docker-compose-dev.yml` (hardcoded `mobsf` for `postgres` service); must match in `cyberspect.env`/`qcluster.env` | DB name, defaults to `mobsf`. |
| `POSTGRES_HOST` | `settings.py:161,168` | `cyberspect.env`/`qcluster.env` (must resolve to the `postgres` service name, e.g. `postgres`) | DB host. |
| `POSTGRES_PORT` | `settings.py:169` | `cyberspect.env`/`qcluster.env` (optional; defaults to `5432`) | DB port, defaults to `5432`. |
| `MOBSF_API_KEY` | `Dockerfile.dev:20`; `init.py:213-215`; `api_middleware.py` | Image `ENV` default in `Dockerfile.dev` (`=1`); overridden by `cyberspect.env` if set there (`env_file` wins over image `ENV`) | Master API key (or `MOBSF_API_KEY_FILE` for Docker secrets) — full-access short-circuit auth. |
| `AWS_SECRET_ACCESS_KEY` | Not referenced directly in app code — same as `AWS_ACCESS_KEY_ID`, standard boto3/AWS SDK credential | `cyberspect.env`/`qcluster.env` locally, or ECS task definitions / GitHub Actions secrets in deployed environments | Implicit AWS SDK credential, not explicitly read by MobSF Python code. |
| `MOBSF_SECRET_KEY` | `init.py:40-41` | `cyberspect.env` if set; otherwise falls back to a `secret` file under the MobSF home dir, auto-generated on first run | Django `SECRET_KEY` override (session/cookie signing, CSRF). |
| `MOBSF_VT_API_KEY` | `settings.py:568` | `cyberspect.env` | VirusTotal API key. |

**Not found as environment variables in this codebase:** `CYBERSPECT_VER`, `ENVIRONMENT`, `LOCAL_AUTH_TOKEN` — each corresponds to something else (a hardcoded constant, a DB field, or an intermediate Python variable, respectively) rather than a settable env var.

**Note on `cyberspect.env`/`qcluster.env`:** these files are not stored in this repo — per `LOCAL-DEV.md`, they're copied in from a separate AWS config repo and referenced via `env_file:` in `docker-compose-dev.yml` for the `mobsf` and `qcluster` services respectively.
