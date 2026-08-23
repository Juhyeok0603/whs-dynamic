import sys
from datetime import datetime, timezone
from typing import Any
from .static_scan import shannon_entropy
from .instrumentation import CODE_LOG_NAME, ENV_LOG_NAME

_SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
_DOWNLOADERS = {"curl", "wget", "certutil"}
_EXFIL_DOMAINS = ("webhook.site", "discord.com", "telegram.org", "pastebin.com", "ngrok.io", "ngrok-free.app", "requestbin.com", "transfer.sh", "file.io", "ptpb.pw", "0x0.st")
_AUTORUN_PATTERNS = (".bashrc", ".bash_profile", ".profile", "/etc/cron", "/etc/systemd", ".config/systemd", ".config/autostart", "/etc/rc.local", "/etc/init.d")
_CI_ENV_KEYS = {"CI", "GITHUB_ACTIONS", "TRAVIS", "JENKINS_URL", "GITLAB_CI", "BUILDKITE", "CIRCLECI"}
_STDLIB = set(getattr(sys, "stdlib_module_names", ()))  # host stdlib set; sandbox runs CPython 3.12 too, close enough
_TIME_NEAR_WINDOW = 5.0
# Our own scaffolding written into the workspace around the sandboxed run (downloaded artifacts, build
# output, instrumentation logs, static-scan extraction) — excluded from "outside package dir" so that
# signal reflects what the analyzed code itself wrote, not our own tooling sharing the same workspace.
_INFRA_TOP_LEVEL_DIRS = ("built", "_src", "_prev_release")
_INFRA_FILES = {"network.pcap", "sitecustomize.py", ENV_LOG_NAME, CODE_LOG_NAME}
_ARTIFACT_SUFFIXES = (".whl", ".tar.gz", ".tgz", ".zip")


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _time_near(events: list[dict], type_a: str, type_b: str, window_s: float = _TIME_NEAR_WINDOW) -> list[dict]:
    """Pairs each type_a event with the nearest later type_b event within window_s seconds. gvisor-sourced
    events share one timestamp per collection batch (set at parse time, not per-syscall), so this degrades
    to "same stage" correlation for those — still meaningful, just not sub-second precise like the
    instrumentation-sourced (env/code) events, which carry real time.time() timestamps."""
    a_events = [e for e in events if e["type"] == type_a]
    b_events = [(e, _parse_ts(e["timestamp"])) for e in events if e["type"] == type_b]
    pairs = []
    for a in a_events:
        ta = _parse_ts(a["timestamp"])
        if ta is None:
            continue
        best = None
        for b, tb in b_events:
            if tb is None or tb < ta:
                continue
            gap = (tb - ta).total_seconds()
            if gap <= window_s and (best is None or gap < best[1]):
                best = (b, gap)
        if best:
            pairs.append({"a": a, "b": best[0], "gap_seconds": round(best[1], 3)})
    return pairs


def build_events_jsonl(events: list[Any], fs_diff: dict, resource_usage: dict, pcap_flows: list[dict], dns_domains: list[str], env_log: list[dict], code_log: list[dict], sni_records: list[dict], finished_at: str, sinkhole_records: list[dict] | None = None) -> list[dict]:
    merged: list[dict] = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in events]
    for kind in ("created", "modified", "deleted"):
        for entry in fs_diff.get(kind, []):
            merged.append({"timestamp": finished_at, "source": "fs-diff", "category": "filesystem", "type": f"filesystem.{kind}", "stage": "filesystem", "pid": None, "data": entry})
    for point in resource_usage.get("proc", {}).get("series", []):
        merged.append({"timestamp": point["t"], "source": "host", "category": "resource", "type": "resource.proc_sample", "stage": "resource", "pid": None, "data": point})
    for point in resource_usage.get("cgroup", {}).get("series", []):
        merged.append({"timestamp": point["t"], "source": "host", "category": "resource", "type": "resource.cgroup_sample", "stage": "resource", "pid": None, "data": point})
    for flow in pcap_flows:
        merged.append({"timestamp": finished_at, "source": "pcap", "category": "network", "type": "network.flow", "stage": "network", "pid": None, "data": flow})
    for domain in dns_domains:
        merged.append({"timestamp": finished_at, "source": "pcap", "category": "dns", "type": "dns.domain_resolved", "stage": "network", "pid": None, "data": {"domain": domain}})
    for record in sni_records:
        merged.append({"timestamp": finished_at, "source": "pcap", "category": "network", "type": "network.tls_sni", "stage": "network", "pid": None, "data": record})
    for row in env_log:
        event_type = "env.bulk_access" if row.get("event") == "bulk_iteration" else "env.key_access"
        merged.append({"timestamp": _iso(row["timestamp"]), "source": "instrumentation", "category": "env", "type": event_type, "stage": row.get("stage", "unknown"), "pid": None, "data": row})
    for row in code_log:
        merged.append({"timestamp": _iso(row["timestamp"]), "source": "instrumentation", "category": "code", "type": f"code.{row.get('event', 'unknown')}", "stage": row.get("stage", "unknown"), "pid": None, "data": row})
    for record in sinkhole_records or []:
        # Typed as network.connect (not a separate type) so it participates in every existing
        # env<->network / file<->network correlation for free, instead of needing its own wiring.
        merged.append({"timestamp": record.get("timestamp", finished_at), "source": "sinkhole", "category": "network", "type": "network.connect", "stage": "unknown", "pid": None, "data": record})
    merged.sort(key=lambda e: e.get("timestamp") or "")
    return merged


def _exec_exe(data: dict) -> str:
    exe = str(data.get("exe", data.get("comm", data.get("executable", ""))))
    return exe.rsplit("/", 1)[-1].lower()


def build_process_signals(events: list[dict]) -> dict:
    commands = [e for e in events if e["type"] == "process.exec"]
    shell_spawns = [e for e in commands if _exec_exe(e["data"]) in _SHELLS]
    downloader_invocations = [e for e in commands if _exec_exe(e["data"]) in _DOWNLOADERS]
    chmod_exec_pairs = _time_near(events, "file.chmod", "process.exec", window_s=10.0)
    chmod_then_exec = [p for p in chmod_exec_pairs if p["a"]["data"].get("path") and p["a"]["data"]["path"] in str(p["b"]["data"])]
    tree: dict[int, dict] = {}
    for e in commands:
        if e.get("pid") is not None:
            tree.setdefault(e["pid"], {"pid": e["pid"], "exe": _exec_exe(e["data"]), "stage": e["stage"]})
    for e in events:
        if e["type"] == "process.fork" and e["data"].get("child_pid") in tree:
            tree[e["data"]["child_pid"]]["ppid"] = e.get("pid")
    return {
        "commands": [{"stage": e["stage"], "pid": e.get("pid"), "exe": _exec_exe(e["data"]), "argv": e["data"].get("argv") or e["data"].get("args")} for e in commands],
        "shell_spawns": [{"stage": e["stage"], "argv": e["data"].get("argv") or e["data"].get("args")} for e in shell_spawns],
        "downloader_invocations": [{"stage": e["stage"], "argv": e["data"].get("argv") or e["data"].get("args")} for e in downloader_invocations],
        "chmod_then_exec": [{"path": p["a"]["data"].get("path"), "stage": p["a"]["stage"], "gap_seconds": p["gap_seconds"]} for p in chmod_then_exec],
        "process_tree": list(tree.values()),
    }


def _has_exec_bit(mode: str | None) -> bool:
    """mode is the oct(...) string ('0o755') FilesystemCollector/gvisor produce — never contains a literal
    'x', so exec permission has to be read off the bits, not matched as a symbolic-notation substring."""
    if not mode:
        return False
    try:
        return bool(int(mode, 8) & 0o111)
    except ValueError:
        return False


def _is_own_infra(path: str, workspace_root: str) -> bool:
    rel = path[len(workspace_root):].lstrip("/\\") if path.startswith(workspace_root) else path
    top = rel.split("/", 1)[0].split("\\", 1)[0]
    if top in _INFRA_TOP_LEVEL_DIRS or rel in _INFRA_FILES:
        return True
    return "/" not in rel and "\\" not in rel and rel.endswith(_ARTIFACT_SUFFIXES)


def _merge_realtime_writes(diff_entries: list[dict], realtime_entries: list[dict]) -> list[dict]:
    """A dropper that writes, chmod+x's, execs, and deletes itself within one analysis never shows up in
    the before/after fs-diff snapshot (absent from both sides of it) — only the syscall-level realtime
    write is left as evidence. Adds those as extra rows, marked so it's clear they weren't confirmed by
    the final snapshot."""
    seen = {e["path"] for e in diff_entries}
    extra = [{"path": r["path"], "stage": r["stage"], "note": "seen only via syscall trace — not present in the before/after snapshot, likely deleted before it"} for r in realtime_entries if r["path"] and r["path"] not in seen]
    return diff_entries + extra


def build_filesystem_signals(fs_diff: dict, events: list[dict], workspace_root: str, declared_deps: set[str]) -> dict:
    created = fs_diff.get("created", [])
    modified = fs_diff.get("modified", [])
    site_prefix = workspace_root.rstrip("/\\") + "/site"
    realtime_writes = [e for e in events if e["type"] == "file.write_outside_site"]
    outside = _merge_realtime_writes(
        [e for e in created + modified if not (e["path"].startswith(site_prefix) or _is_own_infra(e["path"], workspace_root))],
        [{"path": e["data"].get("path"), "stage": e["stage"]} for e in realtime_writes],
    )
    autorun = _merge_realtime_writes(
        [e for e in created + modified if any(pattern in e["path"] for pattern in _AUTORUN_PATTERNS)],
        [{"path": e["data"].get("path"), "stage": e["stage"]} for e in realtime_writes if e["data"].get("kind") == "autorun"],
    )
    sensitive_access = [e for e in events if e["type"] in ("file.read", "file.write")]
    chmod_events = {e["data"].get("path") for e in events if e["type"] == "file.chmod" and _has_exec_bit(e["data"].get("mode"))}
    exec_drop_chmod = [e for e in created if _has_exec_bit(e.get("mode")) and e["path"] in chmod_events]
    loaded_top_modules = {str(e["data"].get("module", "")).split(".")[0] for e in events if e["type"] == "code.import" and e["data"].get("module")}
    undeclared = sorted(m for m in loaded_top_modules if m and m not in _STDLIB and m not in declared_deps and m != "sitecustomize")
    return {
        "created": created,
        "modified": modified,
        "deleted": fs_diff.get("deleted", []),
        "outside_package_dir": outside,
        "sensitive_path_access": [{"stage": e["stage"], "type": e["type"], "path": e["data"].get("path")} for e in sensitive_access],
        "autorun_location_write": autorun,
        "exec_drop_chmod": exec_drop_chmod,
        "declared_vs_loaded_modules": {"declared": sorted(declared_deps), "loaded_undeclared": undeclared},
    }


def build_network_signals(events: list[dict], pcap_flows: list[dict], dns_domains: list[str], sni_records: list[dict], sni_mismatch_records: list[dict], sinkhole_records: list[dict] | None = None) -> dict:
    connections = [e for e in events if e["type"] == "network.connect"]
    domain_entropy = [{"domain": d, "entropy_bits_per_char": round(shannon_entropy(d.split(".")[0]), 2)} for d in dns_domains]
    sinkhole_hosts = [r.get("host") for r in (sinkhole_records or []) if r.get("host")]
    exfil_matches = sorted(set(
        [d for d in dns_domains if any(known in d for known in _EXFIL_DOMAINS)]
        + [h for h in sinkhole_hosts if any(known in h for known in _EXFIL_DOMAINS)]
    ))
    dst_counts: dict[str, int] = {}
    for f in pcap_flows:
        dst_counts[f["dst"]] = dst_counts.get(f["dst"], 0) + 1
    domain_counts: dict[str, int] = {}
    for d in dns_domains:
        domain_counts[d] = domain_counts.get(d, 0) + 1
    retry_patterns = [{"target": k, "count": v} for k, v in {**dst_counts, **domain_counts}.items() if v > 3]
    return {
        "destinations": pcap_flows,
        "dns_domains": dns_domains,
        "domain_entropy": domain_entropy,
        "exfil_channel_matches": exfil_matches,
        "http_body_credential_patterns": (
            {"status": "success", "captures": sinkhole_records}
            if sinkhole_records
            else {"status": "not_implemented", "reason": "sinkhole network mode not enabled for this analysis (network=sinkhole required); only DNS + SNI + flow metadata are observed on the wire"}
        ),
        "tls_sni_records": sni_records,
        "sni_ip_mismatch": sni_mismatch_records,
        "retry_failure_patterns": retry_patterns,
        "connection_events": len(connections),
    }


def build_env_signals(events: list[dict]) -> dict:
    env_events = [e for e in events if e["category"] == "env"]
    bulk = [e for e in env_events if e["type"] == "env.bulk_access"]
    key_access: dict[str, int] = {}
    for e in env_events:
        if e["type"] == "env.key_access" and e["data"].get("key"):
            key_access[e["data"]["key"]] = key_access.get(e["data"]["key"], 0) + 1
    correlated = _time_near(events, "env.bulk_access", "network.connect")
    return {
        "bulk_iteration_count": len(bulk),
        "bulk_iteration_events": [{"stage": e["stage"], "via": e["data"].get("via")} for e in bulk],
        "keys_accessed": key_access,
        "network_after_bulk_access": [{"stage": p["a"]["stage"], "gap_seconds": p["gap_seconds"]} for p in correlated],
    }


def build_timing_signals(resource_usage: dict, stages: list[Any]) -> dict:
    stage_dicts = [s.model_dump() if hasattr(s, "model_dump") else dict(s) for s in stages]
    proc = resource_usage.get("proc", {})
    cgroup = resource_usage.get("cgroup", {})
    series = proc.get("series", [])
    residual = []
    for s in stage_dicts:
        finished = _parse_ts(s["finished_at"])
        if finished is None:
            continue
        after = [p for p in series if (_parse_ts(p["t"]) or finished) > finished]
        if after and any(p["processes"] > 0 for p in after):
            residual.append({"stage": s["name"], "samples_after_exit": len(after)})
    cpu_ratio = None
    if cgroup.get("cpu_usec") and stage_dicts:
        total_duration = sum(s["duration_seconds"] for s in stage_dicts) or 1
        cpu_ratio = round((cgroup["cpu_usec"] / 1_000_000) / total_duration, 3)
    pid_spike = proc.get("processes", 0) >= 8
    return {
        "residual_processes_after_exit": residual,
        "max_processes": proc.get("processes"),
        "max_rss_kb": proc.get("rss_kb"),
        "cpu_seconds_per_wall_second": cpu_ratio,
        "pid_spike": pid_spike,
    }


def build_evasion_signals(events: list[dict]) -> dict:
    env_events = [e for e in events if e["type"] == "env.key_access"]
    ci_checks = [e for e in env_events if e["data"].get("key") in _CI_ENV_KEYS]
    probes = [e for e in events if e["type"] == "evasion.probe"]
    sleeps = [e for e in events if e["type"] == "process.sleep"]
    sleep_then_activity = []
    for sleep in sleeps:
        ts = _parse_ts(sleep["timestamp"])
        if ts is None:
            continue
        after = [e for e in events if e is not sleep and (_parse_ts(e["timestamp"]) or ts) >= ts and e["stage"] == sleep["stage"]]
        if len(after) > 3:
            sleep_then_activity.append({"stage": sleep["stage"], "duration_s": sleep["data"].get("duration_s"), "events_after": len(after)})
    return {
        "ci_env_checks": [{"stage": e["stage"], "key": e["data"]["key"]} for e in ci_checks],
        "virtualization_probes": [{"stage": e["stage"], "path": e["data"].get("path")} for e in probes],
        "sleep_then_activity": sleep_then_activity,
    }


def build_code_signals(events: list[dict], declared_deps: set[str]) -> dict:
    compiles = [e for e in events if e["type"] == "code.compile"]
    eval_exec_calls = [e for e in compiles if not str(e["data"].get("filename") or "").endswith(".py")]
    imports = [e for e in events if e["type"] == "code.import"]
    base64_imports = {e["stage"] for e in imports if str(e["data"].get("module", "")) in ("base64", "binascii")}
    base64_then_exec = [e for e in eval_exec_calls if e["stage"] in base64_imports]
    loaded_top = {str(e["data"].get("module", "")).split(".")[0] for e in imports if e["data"].get("module")}
    dynamic_imports = sorted(m for m in loaded_top if m and m not in _STDLIB and m not in declared_deps and m != "sitecustomize")
    return {
        "eval_exec_calls": [{"stage": e["stage"], "filename": e["data"].get("filename"), "source_preview": e["data"].get("source_head")} for e in eval_exec_calls],
        "base64_then_exec": [{"stage": e["stage"], "filename": e["data"].get("filename")} for e in base64_then_exec],
        "dynamic_imports_undeclared": dynamic_imports,
    }


def build_reputation_context(registry_meta: dict, download_stats: dict, typosquat: dict, static_scan_result: dict, diff_previous: dict, domain_intel: dict) -> dict:
    return {
        "registry": registry_meta,
        "download_stats": download_stats,
        "typosquat": typosquat,
        "static_scan": static_scan_result,
        "diff_against_previous_release": diff_previous,
        "domain_intel": domain_intel,
    }


def build_correlations(events: list[dict]) -> dict:
    chains = []
    for pair in _time_near(events, "file.read", "network.connect"):
        chains.append({"title": "Sensitive file read followed by network activity", "confidence": 0.83, "gap_seconds": pair["gap_seconds"], "events": [pair["a"], pair["b"]]})
    for pair in _time_near(events, "env.bulk_access", "network.connect"):
        chains.append({"title": "Bulk environment variable access followed by network activity", "confidence": 0.7, "gap_seconds": pair["gap_seconds"], "events": [pair["a"], pair["b"]]})
    for pair in _time_near(events, "file.chmod", "process.exec", window_s=10.0):
        chains.append({"title": "File permission change followed by execution", "confidence": 0.75, "gap_seconds": pair["gap_seconds"], "events": [pair["a"], pair["b"]]})
    for pair in _time_near(events, "code.import", "network.connect"):
        if str(pair["a"]["data"].get("module", "")) not in ("urllib", "http", "requests", "socket", "ssl"):
            chains.append({"title": "Dynamically imported module followed by network activity", "confidence": 0.6, "gap_seconds": pair["gap_seconds"], "events": [pair["a"], pair["b"]]})
    return {"chains": chains}


def build_summary(all_signals: dict) -> dict:
    """Compressed factual digest, deliberately not a verdict/score — judgment is out of scope here."""
    process = all_signals["process_signals"]
    fs = all_signals["filesystem_signals"]
    network = all_signals["network_signals"]
    env = all_signals["env_signals"]
    timing = all_signals["timing_signals"]
    evasion = all_signals["evasion_signals"]
    code = all_signals["code_signals"]
    reputation = all_signals["reputation_context"]
    counts = {
        "commands": len(process["commands"]),
        "shell_spawns": len(process["shell_spawns"]),
        "downloader_invocations": len(process["downloader_invocations"]),
        "sensitive_path_access": len(fs["sensitive_path_access"]),
        "outside_package_dir_writes": len(fs["outside_package_dir"]),
        "loaded_undeclared_modules": len(fs["declared_vs_loaded_modules"]["loaded_undeclared"]),
        "exfil_channel_matches": len(network["exfil_channel_matches"]),
        "sni_ip_mismatches": len(network["sni_ip_mismatch"]),
        "env_bulk_iterations": env["bulk_iteration_count"],
        "eval_exec_calls": len(code["eval_exec_calls"]),
        "ci_env_checks": len(evasion["ci_env_checks"]),
        "virtualization_probes": len(evasion["virtualization_probes"]),
        "correlation_chains": len(all_signals["correlations"]["chains"]),
    }
    notable = []
    if process["shell_spawns"]:
        notable.append(f"{len(process['shell_spawns'])} shell process(es) spawned")
    if fs["sensitive_path_access"]:
        notable.append(f"{len(fs['sensitive_path_access'])} sensitive path access(es)")
    if fs["declared_vs_loaded_modules"]["loaded_undeclared"]:
        notable.append("undeclared modules loaded at runtime: " + ", ".join(fs["declared_vs_loaded_modules"]["loaded_undeclared"][:10]))
    if network["exfil_channel_matches"]:
        notable.append("possible exfil channel domains: " + ", ".join(network["exfil_channel_matches"][:10]))
    if network["sni_ip_mismatch"]:
        notable.append(f"{len(network['sni_ip_mismatch'])} TLS SNI/resolved-IP mismatch(es)")
    typosquat = reputation.get("typosquat", {})
    if typosquat.get("candidate"):
        notable.append(f"name resembles popular package '{typosquat['candidate']}' (edit distance {typosquat['distance']})")
    if reputation.get("registry", {}).get("days_since_publish") is not None and reputation["registry"]["days_since_publish"] < 3:
        notable.append(f"analyzed version published only {reputation['registry']['days_since_publish']} day(s) ago")
    if timing["residual_processes_after_exit"]:
        notable.append("process activity observed after a stage's own exit code was returned")
    if evasion["ci_env_checks"] or evasion["virtualization_probes"]:
        notable.append("CI/virtualization detection probes observed")
    return {"counts": counts, "notable": notable}


def build_all(sources: dict) -> dict:
    finished_at = sources["finished_at"]
    events = build_events_jsonl(
        sources["events"], sources["fs_diff"], sources["resource_usage"], sources["pcap_flows"], sources["dns_domains"],
        sources["env_log"], sources["code_log"], sources["sni_records"], finished_at, sources.get("sinkhole_records"),
    )
    sni_mismatch_records = sources.get("sni_mismatch_records", [])
    declared = set(sources.get("declared_deps", ()))
    result: dict[str, Any] = {"events": events}
    result["process_signals"] = build_process_signals(events)
    result["filesystem_signals"] = build_filesystem_signals(sources["fs_diff"], events, sources["workspace_root"], declared)
    result["network_signals"] = build_network_signals(events, sources["pcap_flows"], sources["dns_domains"], sources["sni_records"], sni_mismatch_records, sources.get("sinkhole_records"))
    result["env_signals"] = build_env_signals(events)
    result["timing_signals"] = build_timing_signals(sources["resource_usage"], sources["stages"])
    result["evasion_signals"] = build_evasion_signals(events)
    result["code_signals"] = build_code_signals(events, declared)
    result["reputation_context"] = build_reputation_context(
        sources.get("registry_meta", {}), sources.get("download_stats", {}), sources.get("typosquat", {}),
        sources.get("static_scan", {}), sources.get("diff_previous", {}), sources.get("domain_intel", {}),
    )
    result["correlations"] = build_correlations(events)
    result["summary"] = build_summary(result)
    return result
