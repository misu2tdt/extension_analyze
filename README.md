# ExtAnalyze

Dynamic analysis system for Chrome extensions.

## Status
🚧 Phase 1 — Foundation (Week 1)

## Quick start

\`\`\`bash
docker compose up --build
\`\`\`

API will be available at http://localhost:8000  
Swagger UI: http://localhost:8000/docs

## Project structure

\`\`\`
extanalyze/
├── api/         # FastAPI service
├── worker/      # Celery worker (TBD)
├── sandbox/     # Chromium sandbox (TBD)
└── docs/        # Documentation
\`\`\`