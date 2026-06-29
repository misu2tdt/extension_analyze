from fastapi import FastAPI
from database import engine, Base
from routers import health, jobs

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ExtAnalyze API", version="0.1.0")

@app.get("/")
def root():
    return {"message": "Welcome to ExtAnalyze", "version": "0.1.0"}

app.include_router(health.router)
app.include_router(jobs.router)