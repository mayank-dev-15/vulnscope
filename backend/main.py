"""
VulnScope - Automated Vulnerability Intelligence Platform
Copyright (c) 2026 Mayank Basena
"""

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional
import asyncio
import logging

from .models import (
    CVEResponse, CVEListResponse, StatsResponse,
    AlertConfig, HealthResponse, ErrorResponse
)
from .services.nvd import NVDService
from .services.exploit_db import ExploitDBService
from .services.risk_scorer import RiskScorer
from .database import init_db, get_session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting VulnScope...")
    await init_db()
    yield
    logger.info("Shutting down VulnScope...")


app = FastAPI(
    title="VulnScope API",
    description="Automated Vulnerability Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Health Check ---

@app.get("/api/v1/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat(),
    )


# --- CVE Endpoints ---

@app.get("/api/v1/cves", response_model=CVEListResponse, tags=["CVEs"])
async def list_cves(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    days: Optional[int] = Query(None, description="Filter by last N days"),
    search: Optional[str] = Query(None, description="Search in description"),
):
    """
    List CVEs with optional filtering by severity, date range, and keyword search.
    """
    try:
        nvd_service = NVDService()
        cves, total = await nvd_service.get_cves(
            severity=severity,
            limit=limit,
            offset=offset,
            days=days,
            search=search,
        )
        return CVEListResponse(
            data=cves,
            total=total,
            limit=limit,
            offset=offset,
        )
    except Exception as e:
        logger.error(f"Error fetching CVEs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/cves/{cve_id}", response_model=CVEResponse, tags=["CVEs"])
async def get_cve(cve_id: str):
    """
    Get detailed information for a specific CVE, including exploit availability
    and risk score.
    """
    try:
        nvd_service = NVDService()
        cve = await nvd_service.get_cve_by_id(cve_id)
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")

        # Enrich with exploit data
        exploit_service = ExploitDBService()
        exploits = await exploit_service.get_exploits_for_cve(cve_id)
        cve["exploits"] = exploits

        # Calculate risk score
        risk_scorer = RiskScorer()
        cve["risk_score"] = risk_scorer.calculate(cve)

        return CVEResponse(data=cve)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- Statistics Endpoints ---

@app.get("/api/v1/stats/trends", response_model=StatsResponse, tags=["Statistics"])
async def get_trends(
    days: int = Query(30, ge=1, le=365),
):
    """
    Get vulnerability trends over the specified number of days.
    """
    try:
        nvd_service = NVDService()
        trends = await nvd_service.get_trends(days=days)
        return StatsResponse(data=trends)
    except Exception as e:
        logger.error(f"Error fetching trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats/severity-distribution", tags=["Statistics"])
async def get_severity_distribution():
    """
    Get current severity distribution of all tracked CVEs.
    """
    try:
        nvd_service = NVDService()
        distribution = await nvd_service.get_severity_distribution()
        return JSONResponse(content={"data": distribution})
    except Exception as e:
        logger.error(f"Error fetching severity distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- Alert Configuration ---

@app.post("/api/v1/alerts/configure", tags=["Alerts"])
async def configure_alert(config: AlertConfig):
    """
    Configure vulnerability alerts for specific severity levels or keywords.
    """
    try:
        return JSONResponse(
            content={"status": "configured", "config": config.model_dump()},
            status_code=201,
        )
    except Exception as e:
        logger.error(f"Error configuring alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
