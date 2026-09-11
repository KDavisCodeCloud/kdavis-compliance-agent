-- Migration 001: compliance_tenants, compliance_scans
--
-- Phase 1 of kdavis-compliance-agent. Lives in the same shared Postgres
-- instance as the rest of the Decoded Empire portfolio (microsaas-prod)
-- rather than provisioning new infrastructure -- matches the convention
-- established by kdavis-agentic-platform and kdavis-finops-agent.
-- Confirmed no collision with any existing table there at the time this
-- was written.
--
-- report_json holds the full CIS v3.0.0 gap report (see
-- compliance/gap_report.py) as JSONB rather than normalized per-control
-- rows -- Phase 1 has exactly one framework/version and the shape is
-- small; revisit normalization if/when a second framework version ships.

CREATE TABLE IF NOT EXISTS compliance_tenants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_name        VARCHAR(255) NOT NULL,
    tenant_token        VARCHAR(255) UNIQUE NOT NULL,  -- SHA-256 hash, raw token never stored
    aws_role_arn        TEXT,
    aws_external_id     VARCHAR(64) NOT NULL,
    aws_verified_at     TIMESTAMPTZ,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending_setup',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_scans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES compliance_tenants(id) ON DELETE CASCADE,
    provider            VARCHAR(20) NOT NULL,
    framework           VARCHAR(100),
    status              VARCHAR(20) NOT NULL DEFAULT 'running',
    error_message       TEXT,
    readiness_score     INT,
    controls_assessed   INT,
    report_json         JSONB,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_compliance_scans_tenant ON compliance_scans (tenant_id);

ALTER TABLE compliance_tenants ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all" ON compliance_tenants
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "tenant_read" ON compliance_tenants
  FOR SELECT TO authenticated
  USING (id = (current_setting('app.tenant_id')::uuid));

ALTER TABLE compliance_scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all" ON compliance_scans
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "tenant_read" ON compliance_scans
  FOR SELECT TO authenticated
  USING (tenant_id = (current_setting('app.tenant_id')::uuid));
