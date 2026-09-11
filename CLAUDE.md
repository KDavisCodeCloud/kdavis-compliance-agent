# CLAUDE.md — kdavis-compliance-agent

## What this is

A hosted compliance-gap-analysis service. A customer grants read-only,
revocable access to their cloud account (AWS cross-account IAM role in
Phase 1; Azure Service Principal deferred), and this service scans it and
reports pass/fail against a real, published compliance framework's
technical controls — starting with the **CIS AWS Foundations Benchmark
v3.0.0**.

**Non-negotiable, inherited from `kdavis-cloud-audit` and
`kdavis-finops-agent`: nothing here ever auto-executes a remediation.**
This service only reports gaps; a human fixes them.

## Why CIS-only, and why v3.0.0 (read before touching `compliance/`)

The original portfolio roadmap wanted SOC 2 built first, then a "CIS AWS
Foundations Benchmark v2.0" (that version does not exist — real versions
are 1.2.0, 1.4.0, 3.0.0, and 5.0.0), then HIPAA. Confirmed with Kelvin
2026-09-11 to reorder and narrow Phase 1:

- **CIS AWS Foundations Benchmark has an exact, AWS-published mapping**
  from Security Hub control IDs to CIS control numbers per version. SOC 2
  Common Criteria and HIPAA Security Rule do not have an equivalent
  technical, scan-detectable mapping — they're largely procedural.
  Building either from general knowledge risks misrepresenting compliance
  status to a customer relying on this for a real audit. CIS is the one
  framework this repo can back up accurately, so it ships first, alone.
- **v3.0.0, not v5.0.0** (AWS's own recommended current version): v5.0.0
  tightens control 1.10 to require *hardware* MFA specifically.
  `kdavis-cloud-audit`'s `AWSProvider` only reports "no MFA device at
  all," with no way to distinguish a virtual/software MFA device from a
  hardware key — so mapping that finding to v5.0.0's 1.10 would overstate
  what was actually verified. v3.0.0's equivalent control (any MFA on a
  console-password user) matches what's actually detectable.

**Phase 1 covers exactly 4 CIS v3.0.0 controls** — see
`compliance/cis_v3_mapping.py` for the mapping table and its docstring for
per-control caveats. Every other CIS v3.0.0 control needs either a new
`kdavis-cloud-audit` `AWSProvider` check that doesn't exist yet, or manual
review — never invent a pass/fail for a control this scan can't actually
verify. `compliance/gap_report.py`'s output says so explicitly
(`coverage_note`), not just in a docstring nobody sees.

## Key architectural decision: depends on kdavis-cloud-audit

Same as `kdavis-finops-agent`: no scanning logic is duplicated here. This
repo depends on `kdavis-cloud-audit`
(https://github.com/KDavisCodeCloud/kdavis-cloud-audit) as a package and
reuses `audit.providers.aws.AWSProvider` and
`audit.sanitizer.sanitize_findings` directly, injecting a customer's
assumed cross-account role credentials. If a new AWS check is needed to
cover more CIS controls, it belongs in `kdavis-cloud-audit`'s
`AWSProvider`, with this repo's `requirements.txt` pin bumped to pick it
up — never reimplemented here.

## Control evaluation is deterministic, not LLM-driven

Unlike `kdavis-finops-agent`'s remediation planner, pass/fail against a
compliance control is a factual, deterministic check against the findings
a scan already produced — it must never be left to a model's judgment.
`compliance/cis_v3_mapping.py` is plain Python data with `match(findings)
-> bool` callables; there is no LLM call anywhere in the scan → report
path in Phase 1. (A later phase could add an LLM-written remediation
*narrative* per failing control, same pattern as FinOps's analysis agent —
the pass/fail judgment itself stays rule-based regardless.)

## Stack

Python 3.11+, FastAPI, asyncpg, boto3, pytest. No LangGraph, no LLM SDK in
Phase 1 — see above.

## Database

Shares the same Postgres instance as the rest of the Decoded Empire
portfolio (`microsaas-prod`). Tables prefixed `compliance_*`
(`compliance_tenants`, `compliance_scans`) — confirmed no collision at the
time this was built. RLS follows the `current_setting('app.tenant_id')`
idiom, same as `kdavis-finops-agent`.

## This service needs its own AWS identity, separate from any customer's

Same requirement discovered live in `kdavis-finops-agent`: calling
`sts.assume_role()` requires the caller to already have valid AWS
credentials. `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` must be a
dedicated IAM user scoped to **only** `sts:AssumeRole`, never a
personal/admin credential — permanent infrastructure, not a test
credential.

## Auth

`X-Tenant-Token` header, SHA-256 hashed before lookup — identical shape to
`kdavis-finops-agent`'s `api/middleware/auth.py` (a deliberate
reimplementation per repo, not a shared dependency).

## Non-negotiables (inherited from THD Agentic Systems global rules)

- tenant_id on every table.
- No hardcoded secrets — `COMPLIANCE_AWS_ACCOUNT_ID`, `DATABASE_URL` from
  environment only.
- No auto-execution of any remediation, ever.
- No silent failures — a failed scan is stored with a clear
  `error_message`, never swallowed.
- Never overstate what was verified — every report result must trace back
  to a real, cited control mapping, not an approximation presented as
  exact. Where AWSProvider's finding is a conservative proxy rather than
  an exact match for the control, say so in the mapping table's own data,
  not just a comment.
- Tests written alongside each module, not after.

## Current status

Phase: 1 (CIS AWS Foundations Benchmark v3.0.0, AWS-only) in progress. See
`EXECUTION_ORDER.md`.
