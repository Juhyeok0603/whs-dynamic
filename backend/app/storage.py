import json
from pathlib import Path
from typing import Any


def save_report(root: Path, report: Any) -> Path:
    target = root / report.analysis_id
    (target / "raw").mkdir(parents=True, exist_ok=True)
    (target / "logs").mkdir(exist_ok=True)
    path = target / "report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_report(root: Path, analysis_id: str) -> dict[str, Any] | None:
    path = root / analysis_id / "report.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_log_bundle(root: Path, report: Any, pcap_src: Path | None) -> Path:
    """Writes the logs/<run-id>/ file bundle — package.log, fs-diff.log, exit-code.txt, dns.log,
    netsim.json, network.pcap, gvisor-trace.json, resource.json — as a per-file artifact export
    alongside report.json, matching the sibling npm module's output convention."""
    target = root / report.analysis_id / "logs"
    target.mkdir(parents=True, exist_ok=True)

    package_log = "\n\n".join(f"=== {s.name} (exit {s.exit_code}) ===\n--- stdout ---\n{s.stdout}\n--- stderr ---\n{s.stderr}" for s in report.stages)
    (target / "package.log").write_text(package_log, encoding="utf-8")

    fs = report.filesystem_diff or {}
    fs_lines = [f"CREATED  {e['path']}" for e in fs.get("created", [])] + [f"MODIFIED {e['path']}" for e in fs.get("modified", [])] + [f"DELETED  {e['path']}" for e in fs.get("deleted", [])]
    (target / "fs-diff.log").write_text("\n".join(fs_lines), encoding="utf-8")

    install_stage = next((s for s in report.stages if s.name == "install"), None)
    (target / "exit-code.txt").write_text("" if install_stage is None or install_stage.exit_code is None else str(install_stage.exit_code), encoding="utf-8")

    behavior = report.behavior or {}
    (target / "dns.log").write_text("\n".join(behavior.get("dns_domains", [])), encoding="utf-8")

    # No outbound sinkhole / TLS interception exists yet — written honestly rather than faking captured traffic.
    (target / "netsim.json").write_text(json.dumps({
        "status": "not_implemented",
        "note": "outbound sinkhole / TLS interception is not built; see network.pcap and dns.log for what was actually observed on the wire instead",
    }, indent=2), encoding="utf-8")

    if pcap_src and pcap_src.exists() and pcap_src.stat().st_size > 0:
        (target / "network.pcap").write_bytes(pcap_src.read_bytes())

    (target / "gvisor-trace.json").write_text(json.dumps(behavior, indent=2, default=str), encoding="utf-8")
    (target / "resource.json").write_text(json.dumps(report.resource_usage or {}, indent=2, default=str), encoding="utf-8")
    return target
