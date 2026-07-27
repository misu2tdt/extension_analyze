from sqlalchemy import Column, String, Integer, DateTime, Float, BigInteger
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime
import uuid
from database import Base


class Job(Base):
    __tablename__ = "jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- CRX info ---
    crx_sha256 = Column(String(64), index=True, nullable=False)
    crx_s3_key = Column(String(255), nullable=True)
    crx_size_bytes = Column(BigInteger, nullable=True)

    # --- Extension metadata (parse tu manifest) ---
    extension_name = Column(String(255), nullable=True)
    extension_version = Column(String(50), nullable=True)
    manifest_version = Column(Integer, nullable=True)
    declared_permissions = Column(JSONB, nullable=True)
    declared_host_permissions = Column(JSONB, nullable=True)

    # --- Job lifecycle ---
    status = Column(String(20), default="queued", index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)

    # --- Result ---
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(10), nullable=True)
    behavioral_report = Column(JSONB, nullable=True)

    # --- Artifacts (S3 keys) ---
    pcap_s3_key = Column(String(255), nullable=True)
    screenshots_s3_keys = Column(JSONB, nullable=True)

    # --- Errors ---
    error_message = Column(String, nullable=True)