"""Tenant token authentication.

Every request must include X-Tenant-Token: <token>. The token is
SHA-256 hashed before DB lookup so plaintext tokens are never stored --
identical shape to kdavis-finops-agent's api/middleware/auth.py (a
deliberate reimplementation, not a shared dependency).
"""

import hashlib

from fastapi import HTTPException, Request, status


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def get_tenant(request: Request) -> dict:
    token = request.headers.get("X-Tenant-Token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-Tenant-Token header required")

    token_hash = _hash_token(token)
    db = request.app.state.db_pool

    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, company_name, aws_role_arn, aws_external_id, status "
            "FROM compliance_tenants WHERE tenant_token = $1",
            token_hash,
        )

    if not row:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid tenant token")

    return dict(row)
