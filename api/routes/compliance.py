"""Compliance scan triggering and reporting.

POST /tenants/{tenant_id}/scan   -- builds fresh credentials for whichever
                                     provider the tenant connected, runs
                                     kdavis-cloud-audit's matching
                                     Provider, sanitizes, builds a CIS gap
                                     report, stores it, returns it
                                     synchronously.
GET  /tenants/{tenant_id}/report -- retrieves the latest report.

Azure scanning uses kdavis-cloud-audit's AzureProvider bespoke ARM checks
(CIS 4.1, 4.17, 7.1, 7.2 -- see audit/providers/azure.py) and
compliance/cis_azure_mapping.py's CIS Microsoft Azure Foundations
Benchmark v3.0.0 mapping. These checks are self-contained Reader-scoped
ARM API calls -- they do not depend on Microsoft Defender for Cloud's
Regulatory Compliance API, which requires the customer's subscription to
be on Defender's paid standard pricing tier (confirmed live: a 400 "no
standard pricing bundle" error on a subscription without it).
"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.middleware.auth import get_tenant
from compliance.cis_azure_mapping import CIS_AZURE_CONTROLS, CIS_AZURE_TOTAL_CONTROLS, FRAMEWORK_NAME_AZURE
from compliance.gap_report import build_gap_report
from core.aws_onboarding import AssumeRoleError, assume_role_session
from core.azure_onboarding import build_azure_credential
from security.encryption import decrypt

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


def _collect_findings_and_build_report(tenant: dict) -> dict:
    """Builds fresh credentials, runs the matching kdavis-cloud-audit
    Provider, and returns a CIS gap report. Raises HTTPException for any
    problem that should stop the scan before it starts (no verified
    credentials, unsupported provider) -- distinct from a scan that
    starts but fails partway, which trigger_scan below catches and
    stores as a 'failed' scan row rather than raising."""
    provider = tenant["connected_provider"]

    if provider == "aws":
        if tenant["status"] != "active" or not tenant["aws_role_arn"]:
            raise HTTPException(status_code=400, detail="Tenant has no verified AWS role yet")
        session = assume_role_session(tenant["aws_role_arn"], tenant["aws_external_id"])

        from audit.providers.aws import AWSProvider  # deferred: heavy import, only needed on scan
        from audit.sanitizer import sanitize_findings

        sanitized = sanitize_findings(AWSProvider(session=session).collect())
        return build_gap_report([f.to_dict() for f in sanitized])

    if provider == "azure":
        if tenant["status"] != "active" or not tenant["azure_client_secret_encrypted"]:
            raise HTTPException(status_code=400, detail="Tenant has no verified Azure Service Principal yet")
        credential = build_azure_credential(
            tenant["azure_tenant_id"],
            tenant["azure_client_id"],
            decrypt(tenant["azure_client_secret_encrypted"]),
        )

        from audit.providers.azure import AzureProvider  # deferred: heavy import, only needed on scan
        from audit.sanitizer import sanitize_findings

        sanitized = sanitize_findings(
            AzureProvider(credential=credential, subscription_id=tenant["azure_subscription_id"]).collect()
        )
        return build_gap_report(
            [f.to_dict() for f in sanitized],
            framework_name=FRAMEWORK_NAME_AZURE,
            controls=CIS_AZURE_CONTROLS,
            total_controls=CIS_AZURE_TOTAL_CONTROLS,
        )

    raise HTTPException(status_code=400, detail="Tenant has not connected a cloud provider yet")


@router.post("/{tenant_id}/scan", response_model=ScanReportResponse, status_code=201)
async def trigger_scan(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> ScanReportResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    provider = tenant["connected_provider"]
    start = time.time()
    try:
        report = _collect_findings_and_build_report(tenant)
        status_value, error_message = "ready", None
    except HTTPException:
        raise  # pre-flight rejection (no creds, unsupported provider) -- not a "scan ran and failed" case
    except AssumeRoleError as exc:
        raise HTTPException(status_code=400, detail=f"Could not assume role: {exc}") from exc
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
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            RETURNING id, tenant_id, provider, status, report_json, error_message, started_at, completed_at
            """,
            tenant_id,
            provider,
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
