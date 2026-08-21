from pathlib import Path
from .collectors import EbpfCollector, FilesystemCollector, GvisorStraceCollector, PcapCollector
from .analyzer import analyze
from .package import select_artifact
from .schemas import NormalizedEvent


def test_strace_privilege_escape_dns(tmp_path: Path):
    collector = GvisorStraceCollector(tmp_path)
    (tmp_path / "runsc.log.1.boot").write_text(
        "I0821 22:48:11.000000 100 strace.go:570] [   2:   2] python E setuid(0x0)\n"
        "I0821 22:48:11.000001 100 strace.go:570] [   2:   2] python E unshare(0x10000000)\n"
        "I0821 22:48:11.000002 100 strace.go:570] [   2:   2] python E connect(0x3 socket, {Family: AF_INET, Addr: 8.8.8.8, Port: 53}, 0x10)\n"
    )
    events = collector.collect("execute")
    assert [e.type for e in events] == ["privilege.change", "sandbox.escape_syscall", "network.connect", "dns.query"]
    findings, score, _ = analyze(events)
    assert {f.rule_id for f in findings} >= {"privilege.change_attempt", "sandbox.escape_syscall"}
    assert score >= 70


def test_pcap_and_ebpf_line_parsers():
    assert PcapCollector.parse_line("12:00:00.000001 IP 172.17.0.2.44444 > 8.8.8.8.53: UDP, length 32") == ("172.17.0.2", "8.8.8.8", 53)
    assert PcapCollector.parse_line("garbage") is None
    assert EbpfCollector.parse_line("EXEC pid=123 comm=curl file=/usr/bin/curl") == {"type": "process.exec", "pid": 123, "comm": "curl", "file": "/usr/bin/curl"}
    assert EbpfCollector.parse_line("CONN pid=9 comm=python3") == {"type": "network.connect", "pid": 9, "comm": "python3"}
    assert EbpfCollector.parse_line("EXEC pid=1 comm=dockerd file=/usr/bin/dockerd") is None  # infra noise filtered


def test_select_artifact():
    files = [Path(n) for n in ("urllib3-2.0.7-py3-none-any.whl", "requests-2.31.0-py3-none-any.whl", "requests_toolbelt-1.0.0-py2.py3-none-any.whl")]
    assert select_artifact(files, "requests", "auto").name == "requests-2.31.0-py3-none-any.whl"
    assert select_artifact(files, "requests-toolbelt", "wheel").name == "requests_toolbelt-1.0.0-py2.py3-none-any.whl"
    assert select_artifact(files, "requests", "sdist").name == "requests-2.31.0-py3-none-any.whl"  # falls back when the exact type is absent
    assert select_artifact(files, "flask", "auto") is None


def test_filesystem_diff(tmp_path: Path):
    before = FilesystemCollector().snapshot([tmp_path]); (tmp_path / "x").write_text("x"); after = FilesystemCollector().snapshot([tmp_path])
    assert after["%s" % (tmp_path / "x")]["size"] == 1
    assert len(FilesystemCollector().diff(before, after)["created"]) == 1


def test_gvisor_strace_collector(tmp_path: Path):
    collector = GvisorStraceCollector(tmp_path)
    (tmp_path / "runsc.log.123.boot").write_text(
        'I0821 22:48:11.000000 100 strace.go:570] [   2:   2] python E execve(0x0 /bin/sh, 0x0 ["sh", "-c", "curl x"], 0x0)\n'
        "I0821 22:48:11.000001 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /home/user/.aws/credentials, O_RDONLY)\n"
        "I0821 22:48:11.000002 100 strace.go:570] [   2:   2] python X read(0x3, 0x0, 0x100) = 10\n"
    )
    events = collector.collect("import")
    assert [e.type for e in events] == ["process.exec", "file.read"]
    assert analyze(events)[1] > 0
    assert collector.collect("import") == []


def test_sensitive_read_finding():
    event = NormalizedEvent(source="gvisor", category="file", type="file.read", stage="import", data={"path": "/home/analyzer/.aws/credentials"})
    findings, score, _ = analyze([event])
    assert findings[0].rule_id == "file.sensitive_read"
    assert score >= 45
