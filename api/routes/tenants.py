"""Tenant lifecycle: create, connect an AWS account.

POST  /tenants                    -- create a tenant, returns setup instructions
PATCH /tenants/{id}/aws-role      -- verify a customer-created IAM role
"""

import logging
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware.auth import _hash_token, get_tenant
from core.aws_onboarding import AssumeRoleError, build_permissions_policy, build_trust_policy, generate_external_id, verify_role

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tenants", tags=["tenants"])

_TOKEN_PREFIX = "co_t_"


def _generate_raw_token() -> str:
    return f"{_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


# ── Request / response models ─────────────────────────────────────────────────

class CreateTenantRequest(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=255)


class CreateTenantResponse(BaseModel):
    id: str
    tenant_token: str
    warning: str = "Save this token now — it will not be shown again."
    aws_trust_policy: dict
    aws_permissions_policy: dict
    instructions: str


class ConnectAwsRoleRequest(BaseModel):
    role_arn: str = Field(..., min_length=1)


class TenantStatusResponse(BaseModel):
    id: str
    company_name: str
    status: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=CreateTenantResponse, status_code=201)
async def create_tenant(body: CreateTenantRequest, request: Request) -> CreateTenantResponse:
    compliance_account_id = os.environ.get("COMPLIANCE_AWS_ACCOUNT_ID")
    if not compliance_account_id:
        raise HTTPException(status_code=500, detail="COMPLIANCE_AWS_ACCOUNT_ID not configured on this server")

    raw_token = _generate_raw_token()
    token_hash = _hash_token(raw_token)
    external_id = generate_external_id()

    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO compliance_tenants (company_name, tenant_token, aws_external_id)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            body.company_name,
            token_hash,
            external_id,
        )
    tenant_id = str(row["id"])

    log.info("[Tenants] Created tenant=%s company=%s", tenant_id, body.company_name)

    return CreateTenantResponse(
        id=tenant_id,
        tenant_token=raw_token,
        aws_trust_policy=build_trust_policy(compliance_account_id, external_id),
        aws_permissions_policy=build_permissions_policy(),
        instructions=(
            "In AWS: create an IAM role using aws_trust_policy as its trust "
            "relationship, and attach aws_permissions_policy as an inline "
            "policy (read-only, scoped to exactly what gets scanned). Then "
            f"call PATCH /tenants/{tenant_id}/aws-role with the role's ARN."
        ),
    )


@router.patch("/{tenant_id}/aws-role", response_model=TenantStatusResponse)
async def connect_aws_role(
    tenant_id: str,
    body: ConnectAwsRoleRequest,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> TenantStatusResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        verify_role(body.role_arn, tenant["aws_external_id"])
    except AssumeRoleError as exc:
        raise HTTPException(status_code=400, detail=f"Could not assume role: {exc}") from exc

    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE compliance_tenants
            SET aws_role_arn = $1, aws_verified_at = NOW(), status = 'active'
            WHERE id = $2
            RETURNING id, company_name, status
            """,
            body.role_arn,
            tenant_id,
        )

    log.info("[Tenants] AWS role verified tenant=%s", tenant_id)
    return TenantStatusResponse(id=str(row["id"]), company_name=row["company_name"], status=row["status"])
