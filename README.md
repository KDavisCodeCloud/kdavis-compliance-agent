# kdavis-compliance-agent

A hosted compliance-gap-analysis service. A customer grants this service
read-only, revocable access to their AWS or Azure account — an assumed
IAM role (AWS) or a Service Principal (Azure) — and it scans the account
and reports pass/fail against real, published CIS Foundations Benchmark
controls: **CIS AWS Foundations Benchmark v3.0.0** and **CIS Microsoft
Azure Foundations Benchmark v3.0.0**. Control evaluation is deterministic
Python (`match(findings) -> bool` per control) — there is no model call in the
scan → report path. **Nothing here ever auto-executes a remediation**;
this service only reports gaps, a human fixes them. Built on the same
cross-account scanning foundation as
[kdavis-finops-agent](https://github.com/KDavisCodeCloud/kdavis-finops-agent)
and [kdavis-cloud-audit](https://github.com/KDavisCodeCloud/kdavis-cloud-audit)
— all scanning logic (the `AWSProvider`/`AzureProvider` collectors and
finding sanitizer) is imported from `kdavis-cloud-audit`, not duplicated
here.

**Scope note:** this is a deliberately narrow, technically-defensible
slice of each framework — 4 CIS AWS v3.0.0 controls and 4 CIS Azure
v3.0.0 controls, each chosen because `kdavis-cloud-audit`'s providers
already produce a matching finding. Every report's `coverage_note` says
so explicitly (4 of ~62 AWS controls, 4 of 159 Azure controls) — this is
not a full CIS assessment. See `CLAUDE.md` for why CIS-only (not SOC 2 /
HIPAA) and why v3.0.0 rather than AWS's newer v5.0.0.

## Tech stack

- **Python 3.11+, FastAPI** — `api/main.py`, routers in `api/routes/`
- **asyncpg** against a shared Postgres instance (Supabase transaction
  pooler — `statement_cache_size=0` is required for that pooler mode)
- **boto3** for AWS `sts:AssumeRole` and scanning; **azure-identity** +
  `azure-mgmt-*` for Azure Service Principal auth and scanning
- **`kdavis-cloud-audit`** (installed as a git dependency) — supplies
  `audit.providers.aws.AWSProvider`, `audit.providers.azure.AzureProvider`,
  and `audit.sanitizer.sanitize_findings`
- **cryptography** — encrypts Azure client secrets at rest
  (`security/encryption.py`)
- **pytest / pytest-asyncio / pytest-cov** — 9 test modules under
  `tests/`, one per source module

## Directory structure

```
api/
  main.py                 FastAPI app, CORS, lifespan-managed asyncpg pool
  middleware/auth.py       X-Tenant-Token -> tenant row (SHA-256 hashed lookup)
  routes/tenants.py        POST /tenants, PATCH .../aws-role, PATCH .../azure-credentials
  routes/compliance.py     POST .../scan, GET .../report
compliance/
  cis_v3_mapping.py         CIS AWS Foundations Benchmark v3.0.0 -- 4 controls
  cis_azure_mapping.py      CIS Microsoft Azure Foundations Benchmark v3.0.0 -- 4 controls
  gap_report.py             findings -> pass/fail -> readiness_score -> report dict
core/
  aws_onboarding.py         trust/permissions policy, external ID, assume-role
  azure_onboarding.py       Service Principal setup instructions + verification
  db.py                     asyncpg JSONB codec registration
security/
  encryption.py             Fernet-style encrypt/decrypt for Azure client secrets
db/migrations/
  001_compliance_core.sql              compliance_tenants / compliance_scans, RLS
  002_compliance_azure_onboarding.sql  adds Azure Service Principal columns
tests/                      one test module per source module above
```

## How a customer connects a cloud account

1. `POST /api/v1/tenants` with `{"company_name": "..."}` — returns a
   tenant token (shown once, save it), an AWS trust-policy JSON and
   permissions-policy JSON to paste into AWS, and `azure_setup_instructions`
   for the Azure path.
2a. **AWS:** create an IAM role in AWS using the trust policy and attach
    the permissions policy (read-only, scoped to exactly what gets
    scanned), then `PATCH /api/v1/tenants/{id}/aws-role` with
    `{"role_arn": "..."}` — verifies the role works before marking the
    tenant active.
2b. **Azure:** create a Service Principal per `azure_setup_instructions`,
    then `PATCH /api/v1/tenants/{id}/azure-credentials` with
    `{"azure_tenant_id", "client_id", "client_secret", "subscription_id"}`
    — verifies the Service Principal before marking the tenant active.
    (Connecting Azure clears any previously connected AWS role — a tenant
    has exactly one active `connected_provider` at a time.)
3. `POST /api/v1/tenants/{id}/scan` — runs a real scan against whichever
   provider is connected, returns a CIS gap report synchronously. A scan
   that fails partway is stored with `status: "failed"` and a real
   `error_message`, never swallowed.
4. `GET /api/v1/tenants/{id}/report` any time after — the latest report.

Every request after tenant creation requires an `X-Tenant-Token: <token>`
header.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env`:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string (shared portfolio DB) |
| `ENCRYPTION_KEY` | key used by `security/encryption.py` to encrypt Azure client secrets at rest |
| `COMPLIANCE_AWS_ACCOUNT_ID` | this service's own AWS account ID, embedded in the trust policy customers create |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | this service's **own** dedicated AWS identity, scoped to `sts:AssumeRole` only — never a personal/admin credential |
| `AWS_DEFAULT_REGION` | region for the assumed-role session (default `us-east-1`) |
| `ALLOWED_ORIGINS` | comma-separated CORS origins (default `http://localhost:3000`) |
| `LOG_LEVEL` | default `INFO` |

Azure credentials are supplied per-tenant via `PATCH
/api/v1/tenants/{id}/azure-credentials` and stored encrypted — there is
no global Azure env var.

## Run

```bash
uvicorn api.main:app --reload --port 8002
```

Production (`Procfile`):

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

`GET /health` and `GET /health/db` are available for liveness/readiness
checks. Interactive API docs at `/docs`.

## Test

```bash
pytest tests/ -v
```

---

**Built by** [Kelvin Davis](https://www.linkedin.com/in/kelvin-davis) — flagship product: [Cloud Decoded](https://theclouddecoded.com)
