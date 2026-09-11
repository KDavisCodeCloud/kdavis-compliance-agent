# kdavis-compliance-agent

Compliance gap analysis against the **CIS AWS Foundations Benchmark
v3.0.0**, built on the same cross-account scanning foundation as
[kdavis-finops-agent](https://github.com/KDavisCodeCloud/kdavis-finops-agent)
and [kdavis-cloud-audit](https://github.com/KDavisCodeCloud/kdavis-cloud-audit).
A customer grants read-only, revocable access to their AWS account; this
service scans it and reports pass/fail against real, published CIS
controls. **Nothing here ever auto-executes a remediation.**

**Status:** Phase 1 (CIS AWS Foundations Benchmark v3.0.0, AWS-only,
4 controls) — see `EXECUTION_ORDER.md`.

**Scope note:** Phase 1 automatically assesses 4 of the ~62 controls in
CIS v3.0.0 — the ones `kdavis-cloud-audit`'s `AWSProvider` can verify
today. Every report says so explicitly (`coverage_note`); this is not a
full CIS assessment. See `CLAUDE.md` for why CIS-only and why v3.0.0
rather than SOC 2/HIPAA or CIS v5.0.0.

## How a customer connects their AWS account

1. `POST /tenants` with `{"company_name": "..."}` — returns a tenant
   token (save it, shown once) plus a trust-policy JSON and a
   permissions-policy JSON to paste into AWS.
2. In AWS: create an IAM role using the trust policy and attach the
   permissions policy (read-only, scoped to exactly what gets scanned).
3. `PATCH /tenants/{id}/aws-role` with `{"role_arn": "..."}` — verifies
   the role works before marking the tenant active.
4. `POST /tenants/{id}/scan` — runs a real scan, returns a CIS gap report.
5. `GET /tenants/{id}/report` any time after — the latest report.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in DATABASE_URL, COMPLIANCE_AWS_ACCOUNT_ID
```

## Run

```bash
uvicorn api.main:app --reload --port 8002
```

## Test

```bash
pytest tests/ -v
```
