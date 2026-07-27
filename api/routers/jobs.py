from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
import hashlib
import logging

from database import get_db
from models import Job
from celery_client import celery_client
from services.crx_validator import validate_crx, InvalidCRXError
from services.storage import (
    upload_file_bytes, check_object_exists, generate_presigned_url,
    BUCKET_CRX, BUCKET_PCAP,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/jobs", tags=["jobs"])

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/analyze")
async def create_analyze_job(
    file: UploadFile = File(...),
    timeout: int = Form(60),
    db: Session = Depends(get_db),
):
    """Nhan file CRX, validate, hash, luu MinIO, tao job, enqueue task."""
    # 1. Doc noi dung file
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 50MB)")

    # 2. Validate CRX (magic bytes + version)
    try:
        crx_info = validate_crx(content)
    except InvalidCRXError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CRX: {e}")

    # 3. Hash de dedup
    sha256 = hashlib.sha256(content).hexdigest()
    s3_key = f"{sha256}.crx"

    # 4. Check duplicate: neu da co job 'done' voi cung hash -> tra ket qua cu
    existing = (
        db.query(Job)
        .filter(Job.crx_sha256 == sha256, Job.status == "done")
        .order_by(Job.created_at.desc())
        .first()
    )
    if existing:
        return {
            "job_id": str(existing.id),
            "status": "done",
            "duplicate": True,
            "message": "Extension already analyzed. Returning existing result.",
        }

    # 5. Upload CRX len MinIO (chi khi chua ton tai)
    if not check_object_exists(BUCKET_CRX, s3_key):
        upload_file_bytes(BUCKET_CRX, s3_key, content,
                          content_type="application/x-chrome-extension")
        logger.info(f"Uploaded CRX {s3_key} to MinIO")

    # 6. Tao job record
    job = Job(
        crx_sha256=sha256,
        crx_s3_key=s3_key,
        crx_size_bytes=len(content),
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # 7. Enqueue Celery task
    task = celery_client.send_task(
        "analyze_extension",
        args=[str(job.id), sha256, s3_key, timeout],
    )

    return {
        "job_id": str(job.id),
        "task_id": task.id,
        "status": "queued",
        "crx_info": crx_info,
        "duplicate": False,
        "message": "Analysis started. Poll GET /jobs/{job_id} for status.",
    }


@router.get("/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return {
        "job_id": str(job.id),
        "status": job.status,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "crx_sha256": job.crx_sha256,
        "extension": {
            "name": job.extension_name,
            "version": job.extension_version,
            "manifest_version": job.manifest_version,
            "declared_permissions": job.declared_permissions,
            "declared_host_permissions": job.declared_host_permissions,
        } if job.extension_name else None,
        "risk_score": job.risk_score,
        "risk_level": job.risk_level,
        "behavioral_report": job.behavioral_report,
        "error_message": job.error_message,
    }


@router.get("/{job_id}/pcap")
def get_job_pcap(job_id: str, db: Session = Depends(get_db)):
    """Tra ve presigned URL de tai file PCAP truc tiep tu MinIO."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job or not job.pcap_s3_key:
        raise HTTPException(status_code=404, detail="PCAP not available")
    url = generate_presigned_url(BUCKET_PCAP, job.pcap_s3_key)
    return {"pcap_url": url}


@router.get("/")
def list_jobs(limit: int = 10, db: Session = Depends(get_db)):
    jobs = db.query(Job).order_by(Job.created_at.desc()).limit(limit).all()
    return {
        "count": len(jobs),
        "jobs": [
            {
                "id": str(j.id),
                "status": j.status,
                "extension_name": j.extension_name,
                "risk_level": j.risk_level,
                "risk_score": j.risk_score,
                "created_at": j.created_at.isoformat(),
            }
            for j in jobs
        ],
    }