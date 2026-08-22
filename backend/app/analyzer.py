from .schemas import Finding, NormalizedEvent

_SCORES = {"INFO": 0, "LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 70}
_SHELL_OR_DOWNLOADER = {"curl", "wget", "bash", "sh", "dash", "zsh", "ksh"}


def _exec_info(data: dict) -> tuple[str, str]:
    """Returns (exe basename, argv text) for a process.exec event, matched exactly rather than by substring —
    a blob-wide substring check would false-positive on envp noise like the official Python image's PYTHON_SHA256=...
    Handles both the gVisor-parsed {comm,exe,argv,args} shape and the synthetic {executable,args} shape."""
    if "executable" in data:
        exe = str(data["executable"])
        argv = " ".join(data.get("args") or [])
    else:
        exe = str(data.get("exe", data.get("comm", "")))
        argv = str(data.get("argv", data.get("args", "")))
    return exe.rsplit("/", 1)[-1].lower(), argv.lower()


def analyze(events: list[NormalizedEvent]) -> tuple[list[Finding], int, list[dict]]:
    findings = []
    for event in events:
        text = str(event.data).lower()
        if event.type == "process.exec" and _exec_info(event.data)[0] in _SHELL_OR_DOWNLOADER:
            findings.append(Finding(rule_id="process.shell_or_downloader", title="Shell or downloader process executed", severity="MEDIUM", confidence=.86, stage=event.stage, evidence=[event]))
        elif event.type == "file.read":
            # collection already restricts file.read events to sensitive paths (.aws/.ssh/.netrc/passwd/shadow)
            findings.append(Finding(rule_id="file.sensitive_read", title="Sensitive path read", severity="HIGH", confidence=.9, stage=event.stage, evidence=[event]))
        elif event.type == "network.connect" and ("169.254.169.254" in text or event.data.get("blocked")):
            findings.append(Finding(rule_id="network.metadata_or_blocked", title="Cloud metadata or restricted network access attempted", severity="HIGH", confidence=.92, stage=event.stage, evidence=[event]))
        elif event.type == "process.exec" and event.stage not in ("build", "install"):
            # build/install stages are exempted: that pip invocation is our own harness, not the package's own code
            exe, argv = _exec_info(event.data)
            if exe in ("pip", "pip3") or (exe in ("python", "python3") and "pip" in argv):
                findings.append(Finding(rule_id="python.runtime_install", title="Runtime package installation attempted", severity="HIGH", confidence=.84, stage=event.stage, evidence=[event]))
        elif event.type == "privilege.change":
            findings.append(Finding(rule_id="privilege.change_attempt", title="Privilege change syscall attempted", severity="MEDIUM", confidence=.8, stage=event.stage, evidence=[event]))
        elif event.type == "sandbox.escape_syscall":
            findings.append(Finding(rule_id="sandbox.escape_syscall", title="Sandbox escape-related syscall attempted", severity="CRITICAL", confidence=.85, stage=event.stage, evidence=[event]))
    score = min(100, sum(_SCORES[f.severity] for f in findings))
    severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "INFO"
    chains = []
    sensitive = next((f for f in findings if f.rule_id == "file.sensitive_read"), None)
    connection = next((f for f in findings if f.rule_id.startswith("network.")), None)
    if sensitive and connection:
        chains.append({"title": "Sensitive data access followed by network activity", "confidence": .83, "events": sensitive.evidence + connection.evidence})
    return findings, score, chains
