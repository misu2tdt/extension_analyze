from sqlalchemy import create_engine, Column, String, DateTime, Float
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
import uuid
import os

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/extanalyze")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Job(Base):
    __tablename__ = "jobs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    crx_sha256 = Column(String(64), index=True)
    status = Column(String(20), default="queued", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(10), nullable=True)
    behavioral_report = Column(JSONB, nullable=True)
    error_message = Column(String, nullable=True)