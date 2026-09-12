from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.middleware.auth import _hash_token
from api.routes import tenants


def _make_request(conn) -> SimpleNamespace:
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=pool_ctx)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db_pool=pool)))


class TestCreateTenant:
    async def test_creates_tenant_and_returns_policies(self):
        tenant_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": tenant_id})
        request = _make_request(conn)

        with patch.dict("os.environ", {"COMPLIANCE_AWS_ACCOUNT_ID": "111111111111"}):
            result = await tenants.create_tenant(tenants.CreateTenantRequest(company_name="Acme"), request)

        assert result.id == str(tenant_id)
        assert result.tenant_token.startswith("co_t_")
        assert result.aws_trust_policy["Statement"][0]["Principal"]["AWS"] == "arn:aws:iam::111111111111:root"
        assert "az ad sp create-for-rbac" in result.azure_setup_instructions

        sql, company_name, token_hash, external_id = conn.fetchrow.await_args.args
        assert company_name == "Acme"
        assert token_hash == _hash_token(result.tenant_token)

    async def test_missing_account_id_config_fails_clearly(self):
        request = _make_request(AsyncMock())
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(HTTPException) as exc:
                await tenants.create_tenant(tenants.CreateTenantRequest(company_name="Acme"), request)
        assert exc.value.status_code == 500


class TestConnectAwsRole:
    async def test_verifies_and_activates(self):
        tenant_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": tenant_id, "company_name": "Acme", "status": "active"})
        request = _make_request(conn)
        fake_tenant = {"id": tenant_id, "aws_external_id": "ext-abc"}

        with patch("api.routes.tenants.verify_role") as mock_verify:
            result = await tenants.connect_aws_role(
                str(tenant_id),
                tenants.ConnectAwsRoleRequest(role_arn="arn:aws:iam::222222222222:role/x"),
                request,
                tenant=fake_tenant,
            )

        mock_verify.assert_called_once_with("arn:aws:iam::222222222222:role/x", "ext-abc")
        assert result.status == "active"

    async def test_assume_role_failure_returns_400_and_does_not_write(self):
        tenant_id = uuid4()
        conn = AsyncMock()
        request = _make_request(conn)
        fake_tenant = {"id": tenant_id, "aws_external_id": "ext-abc"}

        with patch("api.routes.tenants.verify_role", side_effect=tenants.AssumeRoleError("access denied")):
            with pytest.raises(HTTPException) as exc:
                await tenants.connect_aws_role(
                    str(tenant_id),
                    tenants.ConnectAwsRoleRequest(role_arn="arn:aws:iam::222222222222:role/x"),
                    request,
                    tenant=fake_tenant,
                )
        assert exc.value.status_code == 400
        conn.fetchrow.assert_not_called()

    async def test_tenant_id_mismatch_404(self):
        request = _make_request(AsyncMock())
        fake_tenant = {"id": uuid4(), "aws_external_id": "ext-abc"}
        with pytest.raises(HTTPException) as exc:
            await tenants.connect_aws_role(
                str(uuid4()),
                tenants.ConnectAwsRoleRequest(role_arn="arn:x"),
                request,
                tenant=fake_tenant,
            )
        assert exc.value.status_code == 404


class TestConnectAzureCredentials:
    async def test_verifies_and_activates(self):
        tenant_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": tenant_id, "company_name": "Acme", "status": "active"})
        request = _make_request(conn)
        fake_tenant = {"id": tenant_id}

        with patch("api.routes.tenants.verify_service_principal") as mock_verify, \
             patch("api.routes.tenants.encrypt", return_value="encrypted-secret") as mock_encrypt:
            result = await tenants.connect_azure_credentials(
                str(tenant_id),
                tenants.ConnectAzureCredentialsRequest(
                    azure_tenant_id="tid", client_id="cid", client_secret="raw-secret", subscription_id="sub",
                ),
                request,
                tenant=fake_tenant,
            )

        mock_verify.assert_called_once_with("tid", "cid", "raw-secret", "sub")
        mock_encrypt.assert_called_once_with("raw-secret")
        assert result.status == "active"

        sql, azure_tenant_id, client_id, encrypted_secret, subscription_id, bound_id = conn.fetchrow.await_args.args
        assert azure_tenant_id == "tid"
        assert encrypted_secret == "encrypted-secret"
        assert bound_id == str(tenant_id)
        assert "connected_provider = 'azure'" in sql
        assert "aws_role_arn = NULL" in sql

    async def test_verification_failure_returns_400_and_does_not_write(self):
        tenant_id = uuid4()
        conn = AsyncMock()
        request = _make_request(conn)
        fake_tenant = {"id": tenant_id}

        with patch("api.routes.tenants.verify_service_principal", side_effect=tenants.AzureConnectError("bad creds")):
            with pytest.raises(HTTPException) as exc:
                await tenants.connect_azure_credentials(
                    str(tenant_id),
                    tenants.ConnectAzureCredentialsRequest(
                        azure_tenant_id="tid", client_id="cid", client_secret="s", subscription_id="sub",
                    ),
                    request,
                    tenant=fake_tenant,
                )
        assert exc.value.status_code == 400
        conn.fetchrow.assert_not_called()

    async def test_tenant_id_mismatch_404(self):
        request = _make_request(AsyncMock())
        fake_tenant = {"id": uuid4()}
        with pytest.raises(HTTPException) as exc:
            await tenants.connect_azure_credentials(
                str(uuid4()),
                tenants.ConnectAzureCredentialsRequest(
                    azure_tenant_id="tid", client_id="cid", client_secret="s", subscription_id="sub",
                ),
                request,
                tenant=fake_tenant,
            )
        assert exc.value.status_code == 404
