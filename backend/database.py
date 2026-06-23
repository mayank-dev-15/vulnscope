"""Database configuration and session management."""

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Float, DateTime, Boolean, Text, JSON
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./vulnscope.db")

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class CVERecord(Base):
    __tablename__ = "cves"

    cve_id = Column(String(20), primary_key=True, index=True)
    description = Column(Text)
    severity = Column(String(20), index=True)
    cvss_score = Column(Float)
    published_date = Column(DateTime, index=True)
    modified_date = Column(DateTime)
    references = Column(JSON, default=[])
    affected_products = Column(JSON, default=[])
    cwe_ids = Column(JSON, default=[])
    exploits = Column(JSON, default=[])
    risk_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True)
    name = Column(String(100))
    severity_filters = Column(JSON, default=[])
    keywords = Column(JSON, default=[])
    notification_channels = Column(JSON, default=[])
    webhook_url = Column(String(500), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialized.")


async def get_session() -> AsyncSession:
    """Get a new database session."""
    async with async_session() as session:
        yield session
