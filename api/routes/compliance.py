"""Compliance scan triggering and reporting.

POST /tenants/{tenant_id}/scan   -- assumes the tenant's stored AWS role
                                     fresh, runs kdavis-cloud-audit's
                                     AWSProvider, sanitizes, builds a CIS
                                     v3.0.0 gap report, stores it, returns
                                     it synchronously.
GET  /tenants/{tenant_id}/report -- retrieves the latest report.
"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.middleware.auth import get_tenant
from compliance.gap_report import build_gap_report
from core.aws_onboarding import AssumeRoleError, assume_role_session

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tenants", tags=["compliance"])


class ScanReportResponse(BaseModel):
    scan_id: str
    tenant_id: str
    status: str
    provider: str
    report: dict | None
    error_message: str | None
    started_at: str
    completed_at: str | None


def _row_to_response(row) -> ScanReportResponse:
    return ScanReportResponse(
        scan_id=str(row["id"]),
        tenant_id=str(row["tenant_id"]),
        status=row["status"],
        provider=row["provider"],
        report=row["report_json"],
        error_message=row["error_message"],
        started_at=row["started_at"].isoformat(),
        completed_at=row["completed_at"].isoformat() if row["completed_at"] else None,
    )


@router.post("/{tenant_id}/scan", response_model=ScanReportResponse, status_code=201)
async def trigger_scan(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> ScanReportResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if tenant["status"] != "active" or not tenant["aws_role_arn"]:
        raise HTTPException(status_code=400, detail="Tenant has no verified AWS role yet")

    try:
        session = assume_role_session(tenant["aws_role_arn"], tenant["aws_external_id"])
    except AssumeRoleError as exc:
        raise HTTPException(status_code=400, detail=f"Could not assume role: {exc}") from exc

    from audit.providers.aws import AWSProvider  # deferred: heavy import, only needed on scan
    from audit.sanitizer import sanitize_findings

    start = time.time()
    try:
        findings = AWSProvider(session=session).collect()
        sanitized = sanitize_findings(findings)
        report = build_gap_report([f.to_dict() for f in sanitized])
        status_value, error_message = "ready", None
    except Exception as exc:  # noqa: BLE001 - convert any scan/report failure into a stored, descriptive error
        log.warning("[Compliance] scan failed for tenant=%s: %s", tenant_id, exc)
        report, status_value, error_message = None, "failed", str(exc)
    duration = time.time() - start

    async with request.app.state.db_pool.acquire() as conn:
        scan_row = await conn.fetchrow(
            """
            INSERT INTO compliance_scans (
                tenant_id, provider, framework, status,
                readiness_score, controls_assessed, report_json, error_message, completed_at
            ) VALUES ($1, 'aws', $2, $3, $4, $5, $6, $7, NOW())
            RETURNING id, tenant_id, provider, status, report_json, error_message, started_at, completed_at
            """,
            tenant_id,
            report["framework"] if report else None,
            status_value,
            report["readiness_score"] if report else None,
            report["controls_assessed"] if report else None,
            report,
            error_message,
        )

    log.info(
        "[Compliance] tenant=%s scan=%s status=%s duration=%.1fs",
        tenant_id, scan_row["id"], status_value, duration,
    )

    return _row_to_response(scan_row)


@router.get("/{tenant_id}/report", response_model=ScanReportResponse)
async def get_latest_report(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> ScanReportResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, tenant_id, provider, status, report_json, error_message, started_at, completed_at "
            "FROM compliance_scans WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT 1",
            tenant_id,
        )

    if not row:
        raise HTTPException(status_code=404, detail="No scans yet for this tenant")

    return _row_to_response(row)
