from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid
from datetime import datetime

from database import get_db
from models import Job
from celery_client import celery_client

router = APIRouter(prefix="/jobs", tags=["jobs"])

@router.post("/analyze")
def create_analyze_job(db: Session = Depends(get_db)):
    """
    Submit a new analysis job.
    For now mock — no file upload, just create job + enqueue.
    """
    # Tạo job trong DB
    job = Job(
        crx_sha256="mock_" + str(uuid.uuid4())[:16],
        status="queued"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    
    # Enqueue Celery task
    task = celery_client.send_task(
        'analyze_extension',
        args=[str(job.id), job.crx_sha256]
    )
    
    return {
        "job_id": str(job.id),
        "task_id": task.id,
        "status": "queued",
        "message": "Analysis started. Poll GET /jobs/{job_id} for status."
    }

@router.get("/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    response = {
        "job_id": str(job.id),
        "status": job.status,
        "created_at": job.created_at.isoformat(),
        "risk_score": job.risk_score,
        "risk_level": job.risk_level,
    }
    
    if job.behavioral_report:
        response["behavioral_report"] = job.behavioral_report
    
    return response

@router.get("/")
def list_jobs(limit: int = 10, db: Session = Depends(get_db)):
    jobs = db.query(Job).order_by(Job.created_at.desc()).limit(limit).all()
    return {
        "count": len(jobs),
        "jobs": [
            {
                "id": str(j.id),
                "status": j.status,
                "risk_level": j.risk_level,
                "created_at": j.created_at.isoformat()
            }
            for j in jobs
        ]
    }