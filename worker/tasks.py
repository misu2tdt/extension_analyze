from celery_app import celery_app
from database import SessionLocal, Job
from datetime import datetime
import time
import random
import uuid

@celery_app.task(bind=True, name='analyze_extension')
def analyze_extension(self, job_id: str, crx_sha256: str):
    db = SessionLocal()
    try:
        # Lấy job từ DB
        job = db.query(Job).filter(Job.id == uuid.UUID(job_id)).first()
        if not job:
            print(f"[Worker] Job {job_id} not found")
            return None
        
        # Update status: running
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()
        
        print(f"[Worker] Starting analysis for {job_id}")
        
        # Simulate stages
        for stage in ["extract", "sandbox", "stimulus", "report"]:
            print(f"[Worker] {stage}...")
            time.sleep(7)
        
        # Fake report
        risk_score = random.uniform(0, 100)
        risk_level = "HIGH" if risk_score > 70 else ("MEDIUM" if risk_score > 40 else "LOW")
        
        report = {
            "indicators": {
                "credential_exfil": random.choice([True, False]),
                "iframe_injection": random.choice([True, False]),
            },
            "network": {
                "total_requests": random.randint(10, 100),
                "external_domains": ["example.com"]
            }
        }
        
        # Update DB: done
        job.status = "done"
        job.finished_at = datetime.utcnow()
        job.risk_score = risk_score
        job.risk_level = risk_level
        job.behavioral_report = report
        db.commit()
        
        print(f"[Worker] Done job {job_id}, risk={risk_level}")
        return {"job_id": job_id, "risk_level": risk_level}
        
    except Exception as e:
        print(f"[Worker] Error: {e}")
        if job:
            job.status = "failed"
            job.error_message = str(e)
            db.commit()
        raise
    finally:
        db.close()