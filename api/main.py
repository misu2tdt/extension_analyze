import logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from contextlib import asynccontextmanager
from fastapi import FastAPI
from database import engine, Base
from routers import health, jobs
from services.storage import ensure_buckets_exist


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    Base.metadata.create_all(bind=engine)
    ensure_buckets_exist()
    yield
    # Shutdown


app = FastAPI(title="ExtAnalyze API", version="0.2.0", lifespan=lifespan)


@app.get("/")
def root():
    return {"message": "Welcome to ExtAnalyze", "version": "0.2.0"}


app.include_router(health.router)
app.include_router(jobs.router)