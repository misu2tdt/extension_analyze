from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from database import get_db
from redis_client import redis_client

router = APIRouter(tags=["health"])

@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute("SELECT 1")
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"
    
    try:
        redis_client.ping()
        redis_status = "ok"
    except Exception as e:
        redis_status = f"error: {e}"
    
    return {
        "status": "ok" if db_status == "ok" and redis_status == "ok" else "degraded",
        "database": db_status,
        "redis": redis_status,
        "timestamp": datetime.utcnow().isoformat()
    }