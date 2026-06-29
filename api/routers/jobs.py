from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid

from database import get_db
from models import Job

router = APIRouter(prefix="/jobs", tags=["jobs"])

@router.post("/")
def create_job(db: Session = Depends(get_db)):
    job = Job(
        crx_sha256="placeholder_" + str(uuid.uuid4())[:8],
        status="queued"
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return {
        "job_id": str(job.id),
        "status": job.status,
        "created_at": job.created_at.isoformat()
    }

@router.get("/")
def list_jobs(limit: int = 10, db: Session = Depends(get_db)):
    jobs = db.query(Job).order_by(Job.created_at.desc()).limit(limit).all()
    return {
        "count": len(jobs),
        "jobs": [
            {"id": str(j.id), "status": j.status, "created_at": j.created_at.isoformat()}
            for j in jobs
        ]
    }

@router.get("/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": str(job.id),
        "status": job.status,
        "created_at": job.created_at.isoformat(),
        "risk_score": job.risk_score,
        "risk_level": job.risk_level
    }