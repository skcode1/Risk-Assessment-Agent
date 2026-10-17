"""
API Version 1 Central Router Configuration.
Aggregates and registers route modules for risk assessments, policies,
investigations, health/readiness probes, and explanation governance.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    health,
    investigations,
    policies,
    risk_assessments,
)

api_router = APIRouter()

# Health and readiness diagnostics
api_router.include_router(
    health.router,
    prefix="/health",
    tags=["System Diagnostics & Readiness"],
)

# Deterministic cyber risk assessment pipeline
api_router.include_router(
    risk_assessments.router,
    prefix="/risk-assessments",
    tags=["Risk Assessments"],
)

# Dynamic policy lifecycle & weight governance
api_router.include_router(
    policies.router,
    prefix="/policies",
    tags=["Risk Policies"],
)

# Investigation telemetry & asset enrichment
api_router.include_router(
    investigations.router,
    prefix="/investigations",
    tags=["Investigations & Telemetry"],
)