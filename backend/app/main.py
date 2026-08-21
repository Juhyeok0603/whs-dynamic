import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException
from .config import settings
from .package import analyze_package
from .schemas import AnalysisRequest
from .storage import load_report

app = FastAPI(title="PyPI DAST MVP", version="0.1.0")
executor = ThreadPoolExecutor(max_workers=2)
jobs: dict[str, str] = {}


@app.get("/health")
def health(): return {"status": "ok"}


@app.post("/api/analysis", status_code=202)
def create_analysis(request: AnalysisRequest):
    analysis_id = str(uuid.uuid4())
    jobs[analysis_id] = "queued"
    executor.submit(_run_analysis, analysis_id, request)
    return {"analysis_id": analysis_id, "status": "queued"}


def _run_analysis(analysis_id: str, request: AnalysisRequest):
    jobs[analysis_id] = "running"
    report = analyze_package(request.package, request.version, request.artifact, request.network, request.timeout, request.custom_command, analysis_id)
    jobs[analysis_id] = report.analysis["status"]


@app.get("/api/analysis")
def list_analysis():
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    return [load_report(settings.data_dir, p.name) for p in settings.data_dir.iterdir() if p.is_dir() and (p / "report.json").exists()]


@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    report = load_report(settings.data_dir, analysis_id)
    if report is None:
        if analysis_id in jobs: return {"analysis_id": analysis_id, "status": jobs[analysis_id]}
        raise HTTPException(404, "analysis not found")
    return report


@app.get("/api/analysis/{analysis_id}/events")
def get_events(analysis_id: str):
    report = get_analysis(analysis_id)
    return [event for stage in report["stages"] for event in stage.get("events", [])]


@app.get("/api/analysis/{analysis_id}/findings")
def get_findings(analysis_id: str): return get_analysis(analysis_id)["findings"]


@app.delete("/api/analysis/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: str):
    if analysis_id not in jobs and load_report(settings.data_dir, analysis_id) is None:
        raise HTTPException(404, "analysis not found")
    jobs.pop(analysis_id, None)
    shutil.rmtree(settings.data_dir / analysis_id, ignore_errors=True)
