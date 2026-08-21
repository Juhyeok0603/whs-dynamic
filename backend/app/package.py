import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from .config import settings
from .schemas import AnalysisReport, NormalizedEvent, StageResult, now
from .collectors import EbpfCollector, FilesystemCollector, GvisorStraceCollector, HostSamplerCollector, PcapCollector, RuntimeCollector
from .analyzer import analyze
from .storage import save_report
from .sandbox import check_runtime, docker_command


def select_artifact(files: list[Path], package: str, artifact: str) -> Path | None:
    """Picks the requested package's artifact out of the workspace (which also holds downloaded dependencies)."""
    norm = lambda s: s.lower().replace("-", "_").replace(".", "_")
    candidates = [p for p in files if re.match(re.escape(norm(package)) + r"_\d", norm(p.name))]
    return next((p for p in candidates if artifact == "auto" or (artifact == "wheel" and p.suffix == ".whl") or (artifact == "sdist" and p.suffix in (".gz", ".zip"))), candidates[0] if candidates else None)


def run_stage(name, command, cwd, timeout, sandboxed=False, network="restricted"):
    started = time.monotonic(); started_at = now()
    try:
        if sandboxed:
            ready, reason, runtime = check_runtime()
            if not ready:
                raise RuntimeError(f"sandbox unavailable: {reason}")
            command = docker_command(cwd, command, network, runtime)
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
        sandbox_ready, sandbox_reason, sandbox_runtime = check_runtime()
        gvisor = GvisorStraceCollector(settings.gvisor_log_dir)
        strace_active = sandbox_ready and sandbox_runtime.endswith("-trace") and gvisor.available()
        try:
            resolve = run_stage("resolve", [sys.executable, "-c", f"print('resolved by pip download: {requested}')"], workspace, 5); stages.append(resolve)
            # Dependencies are downloaded on the host so the sandbox can install offline with --network none.
            download = run_stage("download", [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--retries", "1", "--timeout", "15", "--dest", str(workspace), requested], workspace, 120); stages.append(download)
            selected = select_artifact(list(workspace.iterdir()), package, artifact)
            if selected is None: raise RuntimeError(download.stderr or "No artifact downloaded")
            distribution_type = "wheel" if selected.suffix == ".whl" else "sdist"
            lister = "zipfile" if selected.suffix in (".whl", ".zip") else "tarfile"
            inspect = run_stage("inspect", [sys.executable, "-m", lister, "-l", str(selected)], workspace, 20); stages.append(inspect)
            host_sampler = HostSamplerCollector(); pcap = PcapCollector(network); ebpf = EbpfCollector()
            for collector in (host_sampler, pcap, ebpf): collector.start()
            try:
                if distribution_type == "sdist":
                    build = run_stage("build", ["python", "-m", "pip", "wheel", "--no-deps", "--no-cache-dir", f"/workspace/{selected.name}", "-w", "/workspace/built"], workspace, 90, True, network); stages.append(build)
                install = run_stage("install", ["python", "-m", "pip", "install", "--no-index", "--find-links", "/workspace", "--target", "/workspace/site", f"/workspace/{selected.name}"], workspace, 60, True, network); stages.append(install)
                top = package.lower().replace("-", "_")
                # ponytail: strace is only harvested for import/execute — install/build legitimately run pip and would false-positive the analyzer
                gvisor.mark()
                import_stage = run_stage("import", ["python", "-c", f"import sys; sys.path.insert(0, '/workspace/site'); import {top}"], workspace, 30, True, network); stages.append(import_stage)
                events.extend(gvisor.collect("import"))
                if import_stage.status == "completed":
                    events.append(runtime.event("import", "process.exec", {"executable": "python", "args": ["-c", f"import {top}"], "parent": None}, "process"))
                if custom_command:
                    gvisor.mark()
                    execute = run_stage("execute", custom_command, workspace, 30, True, network); stages.append(execute)
                    events.extend(gvisor.collect("execute"))
            finally:
                for collector in (host_sampler, pcap, ebpf): collector.stop()
            after = fs.snapshot([workspace]); diff = fs.diff(before, after)
            dns_events = [e.model_dump() for e in events if e.category == "dns"] + [dict(source="pcap", **f) for f in pcap.summary() if f["dst_port"] == 53]
            behavior = {"processes": [e.model_dump() for e in events if e.category == "process"], "files": [e.model_dump() for e in events if e.category == "file"], "dns": dns_events, "connections": [e.model_dump() for e in events if e.category == "network"], "privilege": [e.model_dump() for e in events if e.category == "privilege"], "flows": pcap.summary(), "host_boundary": ebpf.observations}
            findings, score, chains = analyze(events)
            finished = now()
            gvisor_status = "strace collector active" if strace_active else (sandbox_reason if not sandbox_ready else f"isolation only: {settings.sandbox_runtime}-trace runtime or {settings.gvisor_log_dir} missing (run scripts/setup_ubuntu.sh)")
            collector_status = {
                "gvisor": gvisor_status,
                "filesystem": "success",
                "runtime": "success",
                "dns": "via gvisor strace + pcap" if strace_active else "unavailable (needs strace collector)",
                "pcap": pcap.status,
                "proc": (f"success ({host_sampler.proc_samples} samples)" if host_sampler.proc_samples else "no runsc processes sampled" if host_sampler.proc_available() else "unavailable (/proc missing)"),
                "cgroup": (f"success ({host_sampler.cgroup_samples} samples)" if host_sampler.cgroup_samples else "no docker cgroups sampled" if host_sampler.cgroup_available() else "unavailable (cgroup v2 missing)"),
                "ebpf": ebpf.status,
            }
            report = AnalysisReport(analysis_id=analysis_id, package={"ecosystem":"pypi", "name":package, "version":version, "distribution":{"type":distribution_type,"filename":selected.name}}, analysis={"started_at":started,"finished_at":finished,"duration_seconds":0,"status":"completed"}, sandbox={"runtime":sandbox_runtime,"network_mode":network}, summary={"risk_score":score,"severity":("CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=40 else "LOW" if score>=20 else "INFO"),"process_events":len(behavior["processes"]),"file_events":len(behavior["files"]),"network_events":len(behavior["connections"]),"dns_queries":len(dns_events),"findings":len(findings)}, stages=stages, findings=findings, behavior=behavior, filesystem_diff=diff, resource_usage=host_sampler.usage(), behavior_chains=chains, collector_status=collector_status, errors=errors)
        except Exception as exc:
            errors.append(str(exc)); report = AnalysisReport(analysis_id=analysis_id, package={"ecosystem":"pypi","name":package,"version":version}, analysis={"started_at":started,"finished_at":now(),"duration_seconds":0,"status":"failed"}, sandbox={"runtime":settings.sandbox_runtime,"network_mode":network}, summary={"risk_score":0,"severity":"INFO","findings":0}, stages=stages, findings=[], behavior={}, filesystem_diff={"created":[],"modified":[],"deleted":[]}, resource_usage={}, behavior_chains=[], collector_status={"filesystem":"success"}, errors=errors)
    report.analysis["duration_seconds"] = round(time.time() - __import__("datetime").datetime.fromisoformat(started).timestamp(), 3)
    save_report(settings.data_dir, report)
    return report
