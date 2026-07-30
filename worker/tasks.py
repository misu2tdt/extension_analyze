import os
import json
import uuid
import shutil
from datetime import datetime
from pathlib import Path

import docker
import boto3
from celery_app import celery_app
from database import SessionLocal, Job
from risk import build_behavioral_report, compute_risk_score

docker_client = docker.from_env()

s3_client = boto3.client(
    "s3",
    endpoint_url=os.environ.get("S3_ENDPOINT", "http://minio:9000"),
    aws_access_key_id=os.environ.get("S3_ACCESS_KEY", "minioadmin"),
    aws_secret_access_key=os.environ.get("S3_SECRET_KEY", "minioadmin123"),
    region_name="us-east-1",
)

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "extanalyze-sandbox:latest")
SHARED_TMP = Path(os.environ.get("SHARED_TMP", "/shared"))


@celery_app.task(bind=True, name="analyze_extension", max_retries=1)
def analyze_extension(self, job_id: str, crx_sha256: str, crx_s3_key: str, timeout: int = 60):
    print(f"[Worker] === Job {job_id} START ===", flush=True)
    db = SessionLocal()
    job = None
    work_dir = None

    try:
        job = db.query(Job).filter(Job.id == uuid.UUID(job_id)).first()
        if not job:
            print(f"[Worker] Job {job_id} not found", flush=True)
            return None

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        SHARED_TMP.mkdir(parents=True, exist_ok=True)
        work_dir = SHARED_TMP / job_id
        output_dir = work_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        crx_path = work_dir / "extension.crx"
        s3_client.download_file("crx", crx_s3_key, str(crx_path))
        print(f"[Worker] Downloaded CRX -> {crx_path}", flush=True)

        # Duong dan tren HOST (khong phai trong worker container) de sandbox mount
        host_work_dir = str(Path(os.environ.get("HOST_SHARED_TMP", "/shared")) / job_id)

        print(f"[Worker] Spawning sandbox for {job_id}", flush=True)
        logs = docker_client.containers.run(
            SANDBOX_IMAGE,
            command=["/work/extension.crx", "/work/output", str(timeout)],
            volumes={host_work_dir: {"bind": "/work", "mode": "rw"}},
            mem_limit="3g",
            nano_cpus=1_000_000_000,
            shm_size="2g",
            cap_add=["NET_ADMIN", "NET_RAW"],
            network_mode="bridge",
            remove=True,
            stdout=True,
            stderr=True,
        )
        print(f"[Worker] Sandbox log tail:\n"
              f"{logs.decode('utf-8', errors='replace')[-1500:]}", flush=True)

        events_path = output_dir / "events.json"
        if not events_path.exists():
            raise RuntimeError("Sandbox did not produce events.json")
        with open(events_path, encoding="utf-8") as f:
            events = json.load(f)

        manifest = events.get("manifest", {})
        job.extension_name = str(manifest.get("name", "Unknown"))[:255]
        job.extension_version = str(manifest.get("version", "Unknown"))[:50]
        job.manifest_version = manifest.get("manifest_version", 0)
        job.declared_permissions = manifest.get("permissions", [])
        job.declared_host_permissions = manifest.get("host_permissions", [])

        report = build_behavioral_report(events)
        risk_score, risk_level, score_breakdown = compute_risk_score(report)
        report["score_breakdown"] = score_breakdown   # luu static/dynamic rieng vao JSONB
        job.risk_score = risk_score
        job.risk_level = risk_level
        job.behavioral_report = report

        screenshot_keys = []
        for ss in sorted(output_dir.glob("screenshot_*.png")):
            key = f"{job_id}/{ss.name}"
            s3_client.upload_file(str(ss), "screenshots", key)
            screenshot_keys.append(key)
        job.screenshots_s3_keys = screenshot_keys

        pcap = output_dir / "capture.pcap"
        if pcap.exists():
            pcap_key = f"{job_id}.pcap"
            s3_client.upload_file(str(pcap), "pcap", pcap_key)
            job.pcap_s3_key = pcap_key

        job.status = "done"
        job.finished_at = datetime.utcnow()
        db.commit()
        print(f"[Worker] === Job {job_id} DONE, risk={risk_level} ({risk_score}) ===",
              flush=True)
        return {"job_id": job_id, "risk_level": risk_level, "risk_score": risk_score}

    except Exception as e:
        import traceback
        traceback.print_exc()
        if job:
            job.status = "failed"
            job.finished_at = datetime.utcnow()
            job.error_message = str(e)[:1000]
            db.commit()
        raise

    finally:
        db.close()
        if work_dir and work_dir.exists():
            try:
                shutil.rmtree(work_dir)
            except Exception as ce:
                print(f"[Worker] cleanup failed: {ce}", flush=True)