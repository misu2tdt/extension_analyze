from celery import Celery
import os

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")

celery_client = Celery(
    'extanalyze',
    broker=REDIS_URL,
    backend=REDIS_URL,
)