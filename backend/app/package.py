import json
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.request import urlopen
from .config import settings
from .schemas import AnalysisReport, NormalizedEvent, StageResult, now
from .collectors import FilesystemCollector, RuntimeCollector
from .analyzer import analyze
from .storage import save_report
from .sandbox import check_runtime, docker_command


def run_stage(name, command, cwd, timeout, sandboxed=False, network="restricted"):
    started = time.monotonic(); started_at = now()
    try:
        if sandboxed:
            ready, reason = check_runtime()
            if not ready:
                raise RuntimeError(f"sandbox unavailable: {reason}")
            command = docker_command(cwd, command, network)
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        status = "completed" if result.returncode == 0 else "failed"
        timed_out = False
        stdout, stderr, code = result.stdout[-settings.max_output_bytes:], result.stderr[-settings.max_output_bytes:], result.returncode
    except subprocess.TimeoutExpired as exc:
        status, timed_out, stdout, stderr, code = "timeout", True, (exc.stdout or "")[-settings.max_output_bytes:], (exc.stderr or "")[-settings.max_output_bytes:], None
    return StageResult(name=name, status=status, started_at=started_at, finished_at=now(), duration_seconds=round(time.monotonic() - started, 3), exit_code=code, stdout=stdout, stderr=stderr, timeout=timed_out)


def analyze_package(package: str, version: str | None = None, artifact="auto", network="restricted", timeout=240, custom_command=None, analysis_id: str | None = None) -> AnalysisReport:
    analysis_id = analysis_id or str(uuid.uuid4()); started = now(); events = []; stages = []; errors = []
    requested = package if version is None else f"{package}=={version}"
    with tempfile.TemporaryDirectory(prefix="pypi-dast-") as temp:
        workspace = Path(temp); fs = FilesystemCollector(); runtime = RuntimeCollector(); before = fs.snapshot([workspace])
        metadata = {}
        try:
            resolve = run_stage("resolve", [sys.executable, "-m", "pip", "index", "versions", package], workspace, 20); stages.append(resolve)
            download = run_stage("download", [sys.executable, "-m", "pip", "download", "--no-deps", "--dest", str(workspace), requested], workspace, 30); stages.append(download)
            files = list(workspace.iterdir()); selected = next((p for p in files if artifact == "auto" or (artifact == "wheel" and p.suffix == ".whl") or (artifact == "sdist" and p.suffix in (".gz", ".zip"))), files[0] if files else None)
            if selected is None: raise RuntimeError(download.stderr or "No artifact downloaded")
            distribution_type = "wheel" if selected.suffix == ".whl" else "sdist"
            inspect = run_stage("inspect", [sys.executable, "-m", "pip", "show", "-f", package], workspace, 20); stages.append(inspect)
            if distribution_type == "sdist":
                build = run_stage("build", ["python", "-m", "pip", "wheel", "--no-deps", "--no-cache-dir", f"/workspace/{selected.name}", "-w", "/workspace/built"], workspace, 90, True, network); stages.append(build)
            install = run_stage("install", ["python", "-m", "pip", "install", "--no-deps", "--target", "/workspace/site", f"/workspace/{selected.name}"], workspace, 60, True, network); stages.append(install)
            top = package.lower().replace("-", "_")
            import_stage = run_stage("import", ["python", "-c", f"import sys; sys.path.insert(0, '/workspace/site'); import {top}"], workspace, 30, True, network); stages.append(import_stage)
            if import_stage.status == "completed":
                events.append(runtime.event("import", "process.exec", {"executable": "python", "args": ["-c", f"import {top}"], "parent": None}, "process"))
            if custom_command:
                execute = run_stage("execute", custom_command, workspace, 30, True, network); stages.append(execute)
            after = fs.snapshot([workspace]); diff = fs.diff(before, after)
            behavior = {"processes": [e.model_dump() for e in events if e.category == "process"], "files": [], "dns": [], "connections": [], "privilege": []}
            findings, score, chains = analyze(events)
            finished = now()
            report = AnalysisReport(analysis_id=analysis_id, package={"ecosystem":"pypi", "name":package, "version":version, "distribution":{"type":distribution_type,"filename":selected.name}}, analysis={"started_at":started,"finished_at":finished,"duration_seconds":0,"status":"completed"}, sandbox={"runtime":settings.sandbox_runtime,"network_mode":network}, summary={"risk_score":score,"severity":("CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=40 else "LOW" if score>=20 else "INFO"),"process_events":len(behavior["processes"]),"file_events":0,"network_events":0,"dns_queries":0,"findings":len(findings)}, stages=stages, findings=findings, behavior=behavior, filesystem_diff=diff, resource_usage={}, behavior_chains=chains, collector_status={"gvisor":"unavailable in local mode","filesystem":"success","runtime":"success","dns":"unavailable","pcap":"unavailable","proc":"unavailable","cgroup":"unavailable","ebpf":"disabled"}, errors=errors)
        except Exception as exc:
            errors.append(str(exc)); report = AnalysisReport(analysis_id=analysis_id, package={"ecosystem":"pypi","name":package,"version":version}, analysis={"started_at":started,"finished_at":now(),"duration_seconds":0,"status":"failed"}, sandbox={"runtime":settings.sandbox_runtime,"network_mode":network}, summary={"risk_score":0,"severity":"INFO","findings":0}, stages=stages, findings=[], behavior={}, filesystem_diff={"created":[],"modified":[],"deleted":[]}, resource_usage={}, behavior_chains=[], collector_status={"filesystem":"success"}, errors=errors)
    report.analysis["duration_seconds"] = round(time.time() - __import__("datetime").datetime.fromisoformat(started).timestamp(), 3)
    save_report(settings.data_dir, report)
    return report
