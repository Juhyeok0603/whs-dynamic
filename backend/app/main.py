import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from packaging.version import InvalidVersion, Version
from .config import settings
from .package import analyze_package
from .schemas import AnalysisRequest, now
from .storage import load_report

app = FastAPI(title="PyPI DAST MVP", version="0.1.0")
executor = ThreadPoolExecutor(max_workers=2)
jobs: dict[str, dict] = {}  # analysis_id -> in-flight job state, until report.json exists on disk
LOG_FILES = ("package.log", "fs-diff.log", "exit-code.txt", "dns.log", "netsim.json", "network.pcap", "gvisor-trace.json", "resource.json")


@app.get("/health")
def health(): return {"status": "ok"}


@app.get("/api/pypi/{package}")
def search_pypi(package: str):
    """Looks up a package on PyPI so the dashboard can offer a version picker before analysis."""
    try:
        r = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=10)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"PyPI lookup failed: {exc}")
    if r.status_code == 404:
        raise HTTPException(404, "package not found on PyPI")
    r.raise_for_status()
    data = r.json()
    def sort_key(v: str):
        try:
            return (0, Version(v))
        except InvalidVersion:
            return (1, v)
    versions = sorted(data.get("releases", {}).keys(), key=sort_key, reverse=True)
    return {"name": data["info"]["name"], "summary": data["info"].get("summary"), "latest_version": data["info"]["version"], "versions": versions}


@app.post("/api/analysis", status_code=202)
def create_analysis(request: AnalysisRequest):
    analysis_id = str(uuid.uuid4())
    total_stages = 5 + (1 if request.custom_command else 0)  # resolve, download, inspect, install, import (+execute)
    jobs[analysis_id] = {"status": "queued", "package": request.package, "version": request.version, "stage": None, "completed_stages": 0, "total_stages": total_stages, "started_at": None, "finished_at": None}
    executor.submit(_run_analysis, analysis_id, request)
    return {"analysis_id": analysis_id, "status": "queued"}


def _run_analysis(analysis_id: str, request: AnalysisRequest):
    jobs[analysis_id].update(status="running", started_at=now())
    def on_stage(name: str, status: str):
        job = jobs[analysis_id]
        job["stage"] = name
        job["completed_stages"] = min(job["completed_stages"] + 1, job["total_stages"])
    report = analyze_package(request.package, request.version, request.artifact, request.network, request.timeout, request.custom_command, analysis_id, on_stage)
    jobs[analysis_id].update(status=report.analysis["status"], finished_at=now())


@app.get("/api/analysis")
def list_analysis():
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    saved = [load_report(settings.data_dir, p.name) for p in settings.data_dir.iterdir() if p.is_dir() and (p / "report.json").exists()]
    saved_ids = {r["analysis_id"] for r in saved}
    pending = [{"analysis_id": aid, **job} for aid, job in jobs.items() if aid not in saved_ids and job["status"] in ("queued", "running")]
    return saved + pending


@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    report = load_report(settings.data_dir, analysis_id)
    if report is None:
        if analysis_id in jobs: return {"analysis_id": analysis_id, **jobs[analysis_id]}
        raise HTTPException(404, "analysis not found")
    return report


@app.get("/api/analysis/{analysis_id}/events")
def get_events(analysis_id: str):
    report = get_analysis(analysis_id)
    return [event for stage in report["stages"] for event in stage.get("events", [])]


@app.get("/api/analysis/{analysis_id}/findings")
def get_findings(analysis_id: str): return get_analysis(analysis_id)["findings"]


@app.get("/api/analysis/{analysis_id}/logs")
def list_logs(analysis_id: str):
    """Lists the logs/<run-id>/ file bundle written by write_log_bundle (package.log, fs-diff.log, etc)."""
    logs_dir = settings.data_dir / analysis_id / "logs"
    if not logs_dir.is_dir():
        raise HTTPException(404, "no log bundle for this analysis")
    return [name for name in LOG_FILES if (logs_dir / name).is_file()]


@app.get("/api/analysis/{analysis_id}/logs/{filename}")
def get_log(analysis_id: str, filename: str):
    if filename not in LOG_FILES:
        raise HTTPException(404, "unknown log file")
    path = settings.data_dir / analysis_id / "logs" / filename
    if not path.is_file():
        raise HTTPException(404, "log file not found")
    if filename == "network.pcap":
        return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=filename)
    return PlainTextResponse(path.read_text(encoding="utf-8", errors="replace"))


@app.delete("/api/analysis/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: str):
    if analysis_id not in jobs and load_report(settings.data_dir, analysis_id) is None:
        raise HTTPException(404, "analysis not found")
    jobs.pop(analysis_id, None)
    shutil.rmtree(settings.data_dir / analysis_id, ignore_errors=True)


# Mounted last so it never shadows the /api/* routes above; serves frontend/index.html at "/".
app.mount("/", StaticFiles(directory=Path(__file__).resolve().parents[2] / "frontend", html=True), name="frontend")
