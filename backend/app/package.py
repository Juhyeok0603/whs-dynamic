import configparser
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


def own_console_scripts(site_dir: Path, package: str) -> list[str]:
    """Reads this package's own [console_scripts] entry points (not its dependencies') so import-only analysis can be extended a step further."""
    norm = lambda s: s.lower().replace("-", "_").replace(".", "_")
    dist_info = next((p for p in site_dir.glob("*.dist-info") if norm(p.name).startswith(norm(package) + "_")), None)
    entry_points_file = dist_info / "entry_points.txt" if dist_info else None
    if not entry_points_file or not entry_points_file.exists():
        return []
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(entry_points_file)
    except configparser.Error:
        return []
    return list(parser["console_scripts"]) if parser.has_section("console_scripts") else []


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


def analyze_package(package: str, version: str | None = None, artifact="auto", network="restricted", timeout=240, custom_command=None, analysis_id: str | None = None, on_stage=None) -> AnalysisReport:
    analysis_id = analysis_id or str(uuid.uuid4()); started = now(); events = []; stages = []; errors = []
    requested = package if version is None else f"{package}=={version}"
    def track(stage_result):
        stages.append(stage_result)
        if on_stage: on_stage(stage_result.name, stage_result.status)
    with tempfile.TemporaryDirectory(prefix="pypi-dast-") as temp:
        workspace = Path(temp); fs = FilesystemCollector(); runtime = RuntimeCollector(); before = fs.snapshot([workspace])
        sandbox_ready, sandbox_reason, sandbox_runtime = check_runtime()
        gvisor = GvisorStraceCollector(settings.gvisor_log_dir)
        strace_active = sandbox_ready and sandbox_runtime.endswith("-trace") and gvisor.available()
        try:
            track(run_stage("resolve", [sys.executable, "-c", f"print('resolved by pip download: {requested}')"], workspace, 5))
            # Dependencies are downloaded on the host so the sandbox can install offline with --network none.
            download = run_stage("download", [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--retries", "1", "--timeout", "15", "--dest", str(workspace), requested], workspace, 120); track(download)
            selected = select_artifact(list(workspace.iterdir()), package, artifact)
            if selected is None: raise RuntimeError(download.stderr or "No artifact downloaded")
            distribution_type = "wheel" if selected.suffix == ".whl" else "sdist"
            lister = "zipfile" if selected.suffix in (".whl", ".zip") else "tarfile"
            track(run_stage("inspect", [sys.executable, "-m", lister, "-l", str(selected)], workspace, 20))
            host_sampler = HostSamplerCollector(); pcap = PcapCollector(network); ebpf = EbpfCollector()
            for collector in (host_sampler, pcap, ebpf): collector.start()
            try:
                # build/install run untrusted setup.py / PEP517 build-backend code, so they're strace-observed too;
                # the analyzer exempts our own "pip install" invocation there instead of skipping collection entirely.
                if distribution_type == "sdist":
                    gvisor.mark()
                    build = run_stage("build", ["python", "-m", "pip", "wheel", "--no-deps", "--no-cache-dir", f"/workspace/{selected.name}", "-w", "/workspace/built"], workspace, 90, True, network); track(build)
                    events.extend(gvisor.collect("build"))
                gvisor.mark()
                install = run_stage("install", ["python", "-m", "pip", "install", "--no-index", "--find-links", "/workspace", "--target", "/workspace/site", f"/workspace/{selected.name}"], workspace, 60, True, network); track(install)
                events.extend(gvisor.collect("install"))
                top = package.lower().replace("-", "_")
                gvisor.mark()
                import_stage = run_stage("import", ["python", "-c", f"import sys; sys.path.insert(0, '/workspace/site'); import {top}"], workspace, 30, True, network); track(import_stage)
                events.extend(gvisor.collect("import"))
                if import_stage.status == "completed":
                    events.append(runtime.event("import", "process.exec", {"executable": "python", "args": ["-c", f"import {top}"], "parent": None}, "process"))
                # Post-import probe: exercise the package's own CLI entry points (if any) past their argument parser,
                # a step further than a bare import without calling arbitrary internal functions. Capped at 3 scripts.
                # The script path is passed via sys.argv (not interpolated into the -c source) since it comes from
                # the analyzed package's own (untrusted) entry_points.txt.
                probe_runner = "import sys, runpy; sys.path.insert(0, '/workspace/site'); path = sys.argv[1]; sys.argv = [path, '--help']; runpy.run_path(path, run_name='__main__')"
                for script in own_console_scripts(workspace / "site", package)[:3]:
                    if not (workspace / "site" / "bin" / script).exists(): continue
                    gvisor.mark()
                    probe = run_stage(f"probe:{script}", ["python", "-c", probe_runner, f"/workspace/site/bin/{script}"], workspace, 15, True, network); track(probe)
                    events.extend(gvisor.collect(f"probe:{script}"))
                if custom_command:
                    gvisor.mark()
                    execute = run_stage("execute", custom_command, workspace, 30, True, network); track(execute)
                    events.extend(gvisor.collect("execute"))
            finally:
                for collector in (host_sampler, pcap, ebpf): collector.stop()
            after = fs.snapshot([workspace]); diff = fs.diff(before, after)
            dns_events = [e.model_dump() for e in events if e.category == "dns"] + [dict(source="pcap", **f) for f in pcap.summary() if f["dst_port"] == 53]
            behavior = {"processes": [e.model_dump() for e in events if e.category == "process"], "files": [e.model_dump() for e in events if e.category == "file"], "dns": dns_events, "connections": [e.model_dump() for e in events if e.category == "network"], "privilege": [e.model_dump() for e in events if e.category == "privilege"], "flows": pcap.summary(), "host_boundary": ebpf.observations, "syscall_totals": gvisor.totals()}
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
