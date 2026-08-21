from .schemas import Finding, NormalizedEvent

_SCORES = {"INFO": 0, "LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 70}


def analyze(events: list[NormalizedEvent]) -> tuple[list[Finding], int, list[dict]]:
    findings = []
    for event in events:
        text = str(event.data).lower()
        if event.type == "process.exec" and any(x in text for x in ("curl", "wget", "bash", "sh")):
            findings.append(Finding(rule_id="process.shell_or_downloader", title="Shell or downloader process executed", severity="MEDIUM", confidence=.86, stage=event.stage, evidence=[event]))
        elif event.type == "file.read" and any(x in text for x in (".aws", ".ssh", ".netrc", "/etc/passwd", "/proc")):
            findings.append(Finding(rule_id="file.sensitive_read", title="Sensitive path read", severity="HIGH", confidence=.9, stage=event.stage, evidence=[event]))
        elif event.type == "network.connect" and ("169.254.169.254" in text or event.data.get("blocked")):
            findings.append(Finding(rule_id="network.metadata_or_blocked", title="Cloud metadata or restricted network access attempted", severity="HIGH", confidence=.92, stage=event.stage, evidence=[event]))
        elif event.type == "process.exec" and any(x in text for x in ("pip", "python -m pip")):
            findings.append(Finding(rule_id="python.runtime_install", title="Runtime package installation attempted", severity="HIGH", confidence=.84, stage=event.stage, evidence=[event]))
    score = min(100, sum(_SCORES[f.severity] for f in findings))
    severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "INFO"
    chains = []
    sensitive = next((f for f in findings if f.rule_id == "file.sensitive_read"), None)
    connection = next((f for f in findings if f.rule_id.startswith("network.")), None)
    if sensitive and connection:
        chains.append({"title": "Sensitive data access followed by network activity", "confidence": .83, "events": sensitive.evidence + connection.evidence})
    return findings, score, chains
