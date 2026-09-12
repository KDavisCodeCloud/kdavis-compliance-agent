from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.routes import compliance
from audit.findings import Category, Finding, Severity


def _make_request(conn) -> SimpleNamespace:
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=pool_ctx)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db_pool=pool)))


def _fake_finding(title: str):
    return Finding(
        provider="aws",
        category=Category.SECURITY,
        severity=Severity.MEDIUM,
        service="IAM",
        resource_type="account",
        resource_id="n/a",
        title=title,
        description="d",
        remediation="r",
    )


class TestTriggerScan:
    async def test_tenant_id_mismatch_404(self):
        request = _make_request(AsyncMock())
        fake_tenant = {"id": uuid4(), "status": "active", "connected_provider": "aws", "aws_role_arn": "arn:x", "aws_external_id": "ext"}
        with pytest.raises(HTTPException) as exc:
            await compliance.trigger_scan(str(uuid4()), request, tenant=fake_tenant)
        assert exc.value.status_code == 404

    async def test_no_verified_role_yet_400(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {
            "id": tenant_id,
            "status": "pending_setup",
            "connected_provider": "aws",
            "aws_role_arn": None,
            "aws_external_id": "ext",
        }
        with pytest.raises(HTTPException) as exc:
            await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400

    async def test_no_provider_connected_400(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {"id": tenant_id, "status": "pending_setup", "connected_provider": None}
        with pytest.raises(HTTPException) as exc:
            await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400
        assert "not connected a cloud provider" in exc.value.detail

    async def test_azure_no_verified_credentials_400(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {
            "id": tenant_id,
            "status": "pending_setup",
            "connected_provider": "azure",
            "azure_client_secret_encrypted": None,
        }
        with pytest.raises(HTTPException) as exc:
            await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400

    async def test_azure_successful_scan_stores_cis_azure_report(self):
        tenant_id = uuid4()
        scan_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": scan_id,
                "tenant_id": tenant_id,
                "provider": "azure",
                "status": "ready",
                "report_json": {
                    "framework": "CIS Microsoft Azure Foundations Benchmark v3.0.0",
                    "readiness_score": 75,
                },
                "error_message": None,
                "started_at": datetime.now(timezone.utc),
                "completed_at": datetime.now(timezone.utc),
            }
        )
        request = _make_request(conn)
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "azure",
            "azure_tenant_id": "tenant-x",
            "azure_client_id": "client-x",
            "azure_client_secret_encrypted": "encrypted-secret",
            "azure_subscription_id": "sub-x",
        }

        fake_provider = MagicMock()
        fake_provider.collect.return_value = [_fake_finding("CIS 4.1: Secure transfer required is disabled")]

        with (
            patch("api.routes.compliance.build_azure_credential", return_value=MagicMock()),
            patch("api.routes.compliance.decrypt", return_value="plaintext-secret"),
            patch("audit.providers.azure.AzureProvider", return_value=fake_provider),
        ):
            result = await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)

        assert result.status == "ready"
        assert result.report["framework"] == "CIS Microsoft Azure Foundations Benchmark v3.0.0"

        insert_args = conn.fetchrow.await_args.args
        assert insert_args[2] == "azure"  # provider
        assert insert_args[4] == "ready"  # status_value

    async def test_assume_role_failure_returns_400(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "aws",
            "aws_role_arn": "arn:aws:iam::222222222222:role/x",
            "aws_external_id": "ext",
        }
        with patch(
            "api.routes.compliance.assume_role_session",
            side_effect=compliance.AssumeRoleError("access denied"),
        ):
            with pytest.raises(HTTPException) as exc:
                await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400

    async def test_successful_scan_stores_report_and_returns_it(self):
        tenant_id = uuid4()
        scan_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": scan_id,
                "tenant_id": tenant_id,
                "provider": "aws",
                "status": "ready",
                "report_json": {"framework": "CIS AWS Foundations Benchmark v3.0.0", "readiness_score": 100},
                "error_message": None,
                "started_at": datetime.now(timezone.utc),
                "completed_at": datetime.now(timezone.utc),
            }
        )
        request = _make_request(conn)
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "aws",
            "aws_role_arn": "arn:aws:iam::222222222222:role/x",
            "aws_external_id": "ext",
        }

        fake_provider = MagicMock()
        fake_provider.collect.return_value = [_fake_finding("Root account has no MFA")]

        with (
            patch("api.routes.compliance.assume_role_session", return_value=MagicMock()),
            patch("audit.providers.aws.AWSProvider", return_value=fake_provider),
        ):
            result = await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)

        assert result.status == "ready"
        assert result.report["readiness_score"] == 100

        insert_args = conn.fetchrow.await_args.args
        assert insert_args[1] == str(tenant_id)  # tenant_id
        assert insert_args[2] == "aws"  # provider
        assert insert_args[4] == "ready"  # status_value

    async def test_scan_failure_is_stored_not_raised(self):
        tenant_id = uuid4()
        scan_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": scan_id,
                "tenant_id": tenant_id,
                "provider": "aws",
                "status": "failed",
                "report_json": None,
                "error_message": "boom",
                "started_at": datetime.now(timezone.utc),
                "completed_at": datetime.now(timezone.utc),
            }
        )
        request = _make_request(conn)
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "aws",
            "aws_role_arn": "arn:aws:iam::222222222222:role/x",
            "aws_external_id": "ext",
        }

        fake_provider = MagicMock()
        fake_provider.collect.side_effect = RuntimeError("boom")

        with (
            patch("api.routes.compliance.assume_role_session", return_value=MagicMock()),
            patch("audit.providers.aws.AWSProvider", return_value=fake_provider),
        ):
            result = await compliance.trigger_scan(str(tenant_id), request, tenant=fake_tenant)

        assert result.status == "failed"
        assert result.error_message == "boom"
        assert result.report is None


class TestGetLatestReport:
    async def test_tenant_id_mismatch_404(self):
        request = _make_request(AsyncMock())
        fake_tenant = {"id": uuid4()}
        with pytest.raises(HTTPException) as exc:
            await compliance.get_latest_report(str(uuid4()), request, tenant=fake_tenant)
        assert exc.value.status_code == 404

    async def test_no_scans_yet_404(self):
        tenant_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        request = _make_request(conn)
        fake_tenant = {"id": tenant_id}

        with pytest.raises(HTTPException) as exc:
            await compliance.get_latest_report(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 404

    async def test_returns_latest_report(self):
        tenant_id = uuid4()
        scan_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(
            return_value={
                "id": scan_id,
                "tenant_id": tenant_id,
                "provider": "aws",
                "status": "ready",
                "report_json": {"readiness_score": 75},
                "error_message": None,
                "started_at": datetime.now(timezone.utc),
                "completed_at": datetime.now(timezone.utc),
            }
        )
        request = _make_request(conn)
        fake_tenant = {"id": tenant_id}

        result = await compliance.get_latest_report(str(tenant_id), request, tenant=fake_tenant)

        assert result.report["readiness_score"] == 75
