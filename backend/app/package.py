import configparser
import email
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
from pathlib import Path
from .config import settings
from .schemas import AnalysisReport, NormalizedEvent, StageResult, now
from .collectors import EbpfCollector, FilesystemCollector, GvisorStraceCollector, HostSamplerCollector, PcapCollector, RuntimeCollector
from .analyzer import analyze
from .storage import save_report, write_log_bundle
from .sandbox import check_runtime, docker_command
from . import instrumentation, pcap_tls, registry, static_scan
from .sinkhole import Sinkhole
from .signals import build_all as build_signals

_DOMAIN_INTEL_LIMIT = 10  # WHOIS + reputation lookups are slow network round-trips; cap per analysis


def _safe_call(fn, *args, fallback=None, **kwargs):
    """Runs a best-effort external/host-side lookup (registry API, WHOIS, static scan, ...) without ever
    letting it take down the whole analysis; failures degrade to an honest 'unavailable' stub."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        return fallback if fallback is not None else {"status": "unavailable", "reason": str(exc)}


def read_package_metadata(artifact_path: Path) -> dict:
    """Reads the artifact's own METADATA/PKG-INFO (RFC 822 headers) for declared dependencies — this works
    even if the PyPI registry lookup fails, since the file ships inside the wheel/sdist itself."""
    raw = None
    try:
        if artifact_path.suffix in (".whl", ".zip"):
            with zipfile.ZipFile(artifact_path) as zf:
                name = next((n for n in zf.namelist() if n.endswith(".dist-info/METADATA")), None)
                raw = zf.read(name).decode("utf-8", errors="replace") if name else None
        else:
            with tarfile.open(artifact_path) as tf:
                name = next((n for n in tf.getnames() if n.endswith("PKG-INFO")), None)
                member = tf.extractfile(name) if name else None
                raw = member.read().decode("utf-8", errors="replace") if member else None
    except (OSError, KeyError, tarfile.TarError, zipfile.BadZipFile):
        pass
    if raw is None:
        return {"declared_dependencies": [], "requires_dist_raw": [], "raw_available": False}
    msg = email.message_from_string(raw)
    requires = msg.get_all("Requires-Dist") or []
    declared = sorted({re.split(r"[\s\[;<>=!()]", r.strip())[0].lower() for r in requires if r.strip()})
    return {"name": msg.get("Name"), "version": msg.get("Version"), "declared_dependencies": declared, "requires_dist_raw": requires, "raw_available": True}


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


def run_stage(name, command, cwd, timeout, sandboxed=False, network="restricted", env=None, dns=None, docker_network=None):
    started = time.monotonic(); started_at = now()
    try:
        if sandboxed:
            ready, reason, runtime = check_runtime()
            if not ready:
                raise RuntimeError(f"sandbox unavailable: {reason}")
            command = docker_command(cwd, command, network, runtime, env=env, dns=dns, docker_network=docker_network)
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
        pcap = None  # may never be constructed if failure happens before the install stage
        raw_files: dict[str, str] = {}
        report_signals: dict = {}
        try:
            track(run_stage("resolve", [sys.executable, "-c", f"print('resolved by pip download: {requested}')"], workspace, 5))
            # Dependencies are downloaded on the host so the sandbox can install offline with --network none.
            download = run_stage("download", [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--retries", "1", "--timeout", "15", "--dest", str(workspace), requested], workspace, 120); track(download)
            selected = select_artifact(list(workspace.iterdir()), package, artifact)
            if selected is None: raise RuntimeError(download.stderr or "No artifact downloaded")
            distribution_type = "wheel" if selected.suffix == ".whl" else "sdist"
            lister = "zipfile" if selected.suffix in (".whl", ".zip") else "tarfile"
            track(run_stage("inspect", [sys.executable, "-m", lister, "-l", str(selected)], workspace, 20))

            # Host-side signal extraction: independent of sandbox network mode, runs whether or not the
            # sandboxed stages below succeed, so it happens right after the artifact is on disk.
            metadata = read_package_metadata(selected)
            registry_meta = _safe_call(registry.fetch_registry_meta, package, version)
            download_stats = _safe_call(registry.fetch_download_stats, package)
            typosquat = _safe_call(registry.typosquat_check, package, settings.data_dir / "_cache", settings.top_packages_cache_ttl_hours)
            try:
                source_root = static_scan.extract_source_tree(selected, workspace / "_src")
                static_scan_result = static_scan.scan_source_tree(source_root)
            except Exception as exc:
                source_root, static_scan_result = None, {"status": "unavailable", "reason": str(exc)}
            diff_previous = (
                _safe_call(static_scan.diff_against_previous_release, package, metadata.get("version") or version, registry_meta.get("release_history", []), source_root, workspace)
                if source_root else {"status": "unavailable", "reason": "source extraction failed"}
            )
            raw_files["package-metadata.json"] = json.dumps(metadata, indent=2, default=str)
            raw_files["registry-meta.json"] = json.dumps(registry_meta, indent=2, default=str)
            raw_files["static-scan.json"] = json.dumps({**static_scan_result, "diff_against_previous_release": diff_previous}, indent=2, default=str)

            instrumentation.write_bootstrap(workspace)
            # sinkhole starts (and its per-analysis docker network + NAT rule go up) before the other
            # collectors, since a failed sinkhole must fail the *whole run* closed to "restricted"
            # (--network none) rather than silently falling through to a real bridge network — pcap and
            # every sandboxed stage below need to know that outcome before they start.
            sinkhole = Sinkhole(workspace, analysis_id) if network == "sinkhole" else None
            if sinkhole:
                sinkhole.start()
            effective_network = network if (sinkhole is None or sinkhole.active) else "restricted"
            host_sampler = HostSamplerCollector(); pcap = PcapCollector(effective_network, workspace / "network.pcap"); ebpf = EbpfCollector()
            for collector in (host_sampler, pcap, ebpf):
                collector.start()
            dns_ip = sinkhole.bind_ip if sinkhole and sinkhole.active else None
            docker_net = sinkhole.docker_network if sinkhole and sinkhole.active else None
            ca_path = "/workspace/mitm-ca.pem" if sinkhole and sinkhole.active else None
            def stage_env(stage: str) -> dict[str, str]:
                return instrumentation.stage_env(stage=stage, ca_path=ca_path)
            try:
                # build/install run untrusted setup.py / PEP517 build-backend code, so they're strace-observed too;
                # the analyzer exempts our own "pip install" invocation there instead of skipping collection entirely.
                if distribution_type == "sdist":
                    gvisor.mark()
                    build = run_stage("build", ["python", "-m", "pip", "wheel", "--no-deps", "--no-cache-dir", f"/workspace/{selected.name}", "-w", "/workspace/built"], workspace, 90, True, effective_network, stage_env("build"), dns_ip, docker_net); track(build)
                    events.extend(gvisor.collect("build"))
                gvisor.mark()
                install = run_stage("install", ["python", "-m", "pip", "install", "--no-index", "--find-links", "/workspace", "--target", "/workspace/site", f"/workspace/{selected.name}"], workspace, 60, True, effective_network, stage_env("install"), dns_ip, docker_net); track(install)
                events.extend(gvisor.collect("install"))
                top = package.lower().replace("-", "_")
                gvisor.mark()
                import_stage = run_stage("import", ["python", "-c", f"import sys; sys.path.insert(0, '/workspace/site'); import {top}"], workspace, 30, True, effective_network, stage_env("import"), dns_ip, docker_net); track(import_stage)
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
                    probe = run_stage(f"probe:{script}", ["python", "-c", probe_runner, f"/workspace/site/bin/{script}"], workspace, 15, True, effective_network, stage_env(f"probe:{script}"), dns_ip, docker_net); track(probe)
                    events.extend(gvisor.collect(f"probe:{script}"))
                if custom_command:
                    gvisor.mark()
                    execute = run_stage("execute", custom_command, workspace, 30, True, effective_network, stage_env("execute"), dns_ip, docker_net); track(execute)
                    events.extend(gvisor.collect("execute"))
            finally:
                for collector in (host_sampler, pcap, ebpf, sinkhole):
                    if collector: collector.stop()

            env_log = instrumentation.read_jsonl(workspace / instrumentation.ENV_LOG_NAME)
            code_log = instrumentation.read_jsonl(workspace / instrumentation.CODE_LOG_NAME)
            raw_files["env-access.log"] = "\n".join(json.dumps(row, default=str) for row in env_log)
            raw_files["code-exec.log"] = "\n".join(json.dumps(row, default=str) for row in code_log)
            sni_records = _safe_call(pcap_tls.extract_sni_records, pcap.pcap_path, fallback=[]) if pcap.pcap_path.exists() else []
            dns_answers = _safe_call(pcap_tls.extract_dns_answers, pcap.pcap_path, fallback={}) if pcap.pcap_path.exists() else {}
            sni_mismatch_records = pcap_tls.sni_mismatches(sni_records, dns_answers)
            domain_intel = {}
            for domain in pcap.domains()[:_DOMAIN_INTEL_LIMIT]:
                domain_intel[domain] = {
                    "entropy_bits_per_char": round(static_scan.shannon_entropy(domain.split(".")[0]), 2),
                    "whois": _safe_call(registry.whois_lookup, domain, settings.whois_timeout),
                    "reputation": _safe_call(registry.domain_reputation, domain),
                }
            raw_files["domain-intel.json"] = json.dumps(domain_intel, indent=2, default=str)
            sinkhole_records = sinkhole.records() if sinkhole and sinkhole.active else []
            if sinkhole:
                raw_files["netsim.json"] = json.dumps(sinkhole.to_netsim_json(), indent=2, default=str)

            after = fs.snapshot([workspace]); diff = fs.diff(before, after)
            dns_events = [e.model_dump() for e in events if e.category == "dns"] + [dict(source="pcap", **f) for f in pcap.summary() if f["dst_port"] == 53]
            behavior = {"processes": [e.model_dump() for e in events if e.category == "process"], "files": [e.model_dump() for e in events if e.category == "file"], "dns": dns_events, "dns_domains": pcap.domains(), "connections": [e.model_dump() for e in events if e.category == "network"], "privilege": [e.model_dump() for e in events if e.category == "privilege"], "flows": pcap.summary(), "host_boundary": ebpf.observations, "syscall_totals": gvisor.totals()}
            findings, score, chains = analyze(events)
            finished = now()
            try:
                report_signals = build_signals({
                    "events": events, "fs_diff": diff, "resource_usage": host_sampler.usage(), "pcap_flows": pcap.summary(),
                    "dns_domains": pcap.domains(), "env_log": env_log, "code_log": code_log, "sni_records": sni_records,
                    "sni_mismatch_records": sni_mismatch_records, "declared_deps": metadata.get("declared_dependencies", []),
                    "workspace_root": str(workspace), "stages": stages, "finished_at": finished,
                    "registry_meta": registry_meta, "download_stats": download_stats, "typosquat": typosquat,
                    "static_scan": static_scan_result, "diff_previous": diff_previous, "domain_intel": domain_intel,
                    "sinkhole_records": sinkhole_records, "dns_answers": dns_answers,
                })
            except Exception as exc:
                report_signals = {}
                errors.append(f"signal extraction failed: {exc}")
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
                "sinkhole": sinkhole.status if sinkhole else "not used (network != sinkhole)",
            }
            report = AnalysisReport(analysis_id=analysis_id, package={"ecosystem":"pypi", "name":package, "version":version, "distribution":{"type":distribution_type,"filename":selected.name}}, analysis={"started_at":started,"finished_at":finished,"duration_seconds":0,"status":"completed"}, sandbox={"runtime":sandbox_runtime,"network_mode":effective_network}, summary={"risk_score":score,"severity":("CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=40 else "LOW" if score>=20 else "INFO"),"process_events":len(behavior["processes"]),"file_events":len(behavior["files"]),"network_events":len(behavior["connections"]),"dns_queries":len(dns_events),"findings":len(findings)}, stages=stages, findings=findings, behavior=behavior, filesystem_diff=diff, resource_usage=host_sampler.usage(), behavior_chains=chains, collector_status=collector_status, errors=errors, signals=report_signals)
        except Exception as exc:
            errors.append(str(exc)); report = AnalysisReport(analysis_id=analysis_id, package={"ecosystem":"pypi","name":package,"version":version}, analysis={"started_at":started,"finished_at":now(),"duration_seconds":0,"status":"failed"}, sandbox={"runtime":settings.sandbox_runtime,"network_mode":network}, summary={"risk_score":0,"severity":"INFO","findings":0}, stages=stages, findings=[], behavior={}, filesystem_diff={"created":[],"modified":[],"deleted":[]}, resource_usage={}, behavior_chains=[], collector_status={"filesystem":"success"}, errors=errors)
        # Written while the workspace (and its raw network.pcap) still exist, in both the success and failure case.
        write_log_bundle(settings.data_dir, report, pcap.pcap_path if pcap else None, raw_files)
    report.analysis["duration_seconds"] = round(time.time() - __import__("datetime").datetime.fromisoformat(started).timestamp(), 3)
    save_report(settings.data_dir, report)
    return report
