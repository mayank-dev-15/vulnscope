"""VulnScope Data Models"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CVEItem(BaseModel):
    cve_id: str
    description: str
    severity: SeverityLevel
    cvss_score: float = Field(ge=0, le=10)
    published_date: datetime
    modified_date: datetime
    references: List[str] = []
    affected_products: List[str] = []
    cwe_ids: List[str] = []
    exploits: List[Dict[str, Any]] = []
    risk_score: Optional[float] = None


class CVEResponse(BaseModel):
    data: Dict[str, Any]


class CVEListResponse(BaseModel):
    data: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


class TrendData(BaseModel):
    date: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class StatsResponse(BaseModel):
    data: List[TrendData]


class AlertConfig(BaseModel):
    name: str
    severity_filters: List[SeverityLevel] = []
    keywords: List[str] = []
    notification_channels: List[str] = []  # slack, discord, telegram, email
    webhook_url: Optional[str] = None
    is_active: bool = True


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
