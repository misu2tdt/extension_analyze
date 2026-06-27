from fastapi import FastAPI

app = FastAPI(title="ExtAnalyze API", version="0.1.0")

@app.get("/")
def root():
    return {"message": "Welcome to ExtAnalyze", "version": "0.1.0"}

@app.get("/health")
def health():
    return {"status": "ok"}