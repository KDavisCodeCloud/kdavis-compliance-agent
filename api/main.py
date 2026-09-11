"""kdavis-compliance-agent -- FastAPI application entry point.

Run locally:
    uvicorn api.main:app --reload --port 8002
"""

# ruff: noqa: E402  -- load_dotenv() must run before any os.environ read below

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

import asyncpg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import compliance, tenants
from core.db import register_jsonb_codec

log = logging.getLogger(__name__)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url:
        raise EnvironmentError("DATABASE_URL not set")

    asyncpg_url = database_url.replace("postgresql+asyncpg://", "postgresql://")

    # statement_cache_size=0: same fix as kdavis-agentic-platform and
    # kdavis-finops-agent -- this DATABASE_URL points at Supabase's
    # transaction-mode pooler, which doesn't pin a client to one
    # server-side connection across statements.
    app.state.db_pool = await asyncpg.create_pool(
        asyncpg_url,
        min_size=1,
        max_size=5,
        command_timeout=60,
        statement_cache_size=0,
        init=register_jsonb_codec,
    )
    log.info("[API] Database pool created")

    yield

    await app.state.db_pool.close()
    log.info("[API] Shutdown complete")


app = FastAPI(
    title="Compliance Agent API",
    description="CIS AWS Foundations Benchmark v3.0.0 gap analysis.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_allowed_origins = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "compliance-agent-api"}


@app.get("/health/db")
async def health_db() -> dict:
    async with app.state.db_pool.acquire() as conn:
        await conn.fetchval("SELECT 1")
    return {"status": "ok", "db": "connected"}


app.include_router(tenants.router, prefix="/api/v1")
app.include_router(compliance.router, prefix="/api/v1")
