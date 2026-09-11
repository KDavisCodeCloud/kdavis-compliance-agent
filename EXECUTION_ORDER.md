# EXECUTION_ORDER.md — kdavis-compliance-agent

Numbered phase sequence. Do not reorder. Do not start the next phase
without Kelvin's go-ahead — each phase ends with a status summary and a
stop, same discipline as `kdavis-cloud-audit` and `kdavis-finops-agent`.

## Phase 1 — CIS AWS Foundations Benchmark v3.0.0, AWS-only (in progress)

1. Repo scaffold, `db/migrations/001_compliance_core.sql`
   (`compliance_tenants`/`compliance_scans`, RLS + service-role-first
   policies).
2. `core/aws_onboarding.py` — same external-ID / trust-policy /
   permissions-policy / assume-role pattern as `kdavis-finops-agent`,
   copied fresh (not shared as a dependency between the two agent repos).
3. `api/middleware/auth.py` — `X-Tenant-Token` auth, same shape as
   `kdavis-finops-agent`.
4. `api/routes/tenants.py` — `POST /tenants`, `PATCH /tenants/{id}/aws-role`.
5. `compliance/cis_v3_mapping.py` — the 4-control CIS v3.0.0 mapping table
   (data only, deterministic `match(findings) -> bool` per control). See
   CLAUDE.md for why exactly these 4 and why v3.0.0.
6. `compliance/gap_report.py` — findings -> pass/fail per control ->
   readiness score -> report dict, with an explicit `coverage_note` and a
   manual-review `documentation_checklist`. No LLM call.
7. `api/routes/compliance.py` — `POST /tenants/{id}/scan` (assume role,
   run `AWSProvider(session=...).collect()`, sanitize, build gap report,
   store, return synchronously), `GET /tenants/{id}/report` (latest
   report).
8. Tests alongside every module above (mock `boto3`/`asyncpg`, no real AWS
   calls in unit tests) — plus explicit pass and fail cases for each of
   the 4 control matchers.
9. Live verification: apply the migration to the shared DB, deploy to
   Railway, run one real scan against a test IAM role in Kelvin's AWS
   account, confirm the report is accurate, then destroy the test role
   immediately (standing instruction — the deployed service's own
   dedicated `sts:AssumeRole`-only IAM user is the only thing that stays).

**Phase 1 complete signal:** `✅ COMPLIANCE AGENT CORE READY`. Stop and wait.

## Phase 2 — Expand CIS v3.0.0 coverage (not started)

Add new `kdavis-cloud-audit` `AWSProvider` checks (CloudTrail enabled +
multi-region, S3 Block Public Access, security group unrestricted
ingress, IAM password policy, Config enabled, KMS key rotation, etc.) to
cover more of CIS v3.0.0's ~62 controls beyond the 4 in Phase 1. Each new
control added here must cite the exact Security Hub control ID and CIS
control number, same discipline as Phase 1's mapping table.

## Phase 3 — SOC 2 / HIPAA (not started, needs its own scoping)

Deferred until there's a real, defensible way to map either framework's
largely-procedural controls to something this scan can actually verify,
without inventing mappings from general knowledge. Needs its own plan
before starting, not an assumption carried over from the original
roadmap.

## Phase 4 — Azure onboarding (not started)

Same shape as `kdavis-finops-agent` Phase 2: Service Principal,
`AzureProvider(credential=..., subscription_id=...)` from
`kdavis-cloud-audit`, reusing the same scan/report flow.

## Phase 5 — Frontend dashboard (not started)

Mirrors Cloud Decoded's Cloud Audit tab pattern. Decide then whether this
lives as its own route or inside an existing dashboard, per the
portfolio's `no-separate-dashboards` convention.

## Phase 6 — Billing (not started)

Stripe subscription gating, once there's a product to charge for.
