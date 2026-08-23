import json
import shutil
import socket
import struct
from pathlib import Path
import pytest
from .collectors import EbpfCollector, FilesystemCollector, GvisorStraceCollector, PcapCollector
from .analyzer import analyze
from .package import own_console_scripts, select_artifact
from .schemas import NormalizedEvent
from . import pcap_tls, registry, signals, sinkhole, static_scan


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


def test_pip_platform_probe_not_flagged_as_shell(tmp_path: Path):
    """Regression: pip's own lsb_release/uname platform-detection calls during install must not be flagged as
    'shell or downloader' just because the official Python image's PYTHON_SHA256=... env var contains 'sh'."""
    collector = GvisorStraceCollector(tmp_path)
    (tmp_path / "runsc.log.1.boot").write_text(
        'I0822 11:39:20.000000 100 strace.go:570] [   2:   2] python E execve(0x0 /bin/lsb_release, 0x0 ["lsb_release", "-a"], '
        '0x0 ["HOSTNAME=x", "PYTHON_SHA256=5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a", "HOME=/"])\n'
    )
    events = collector.collect("install")
    assert events[0].data["exe"] == "/bin/lsb_release"
    findings, score, _ = analyze(events)
    assert findings == []
    assert score == 0


def test_pcap_and_ebpf_line_parsers():
    assert PcapCollector.parse_line("12:00:00.000001 IP 172.17.0.2.44444 > 8.8.8.8.53: UDP, length 32") == ("172.17.0.2", "8.8.8.8", 53)
    assert PcapCollector.parse_line("garbage") is None
    assert PcapCollector.parse_dns_name("11:22:33.000001 IP 172.17.0.2.53912 > 8.8.8.8.53: 12345+ A? example.com. (29)") == "example.com"
    assert PcapCollector.parse_dns_name("11:22:33.000002 IP 8.8.8.8.53 > 172.17.0.2.53912: 12345 1/0/0 A 93.184.216.34 (45)") is None
    assert EbpfCollector.parse_line("EXEC pid=123 comm=curl file=/usr/bin/curl") == {"type": "process.exec", "pid": 123, "comm": "curl", "file": "/usr/bin/curl"}
    assert EbpfCollector.parse_line("CONN pid=9 comm=python3") == {"type": "network.connect", "pid": 9, "comm": "python3"}
    assert EbpfCollector.parse_line("EXEC pid=1 comm=dockerd file=/usr/bin/dockerd") is None  # infra noise filtered


def test_select_artifact():
    files = [Path(n) for n in ("urllib3-2.0.7-py3-none-any.whl", "requests-2.31.0-py3-none-any.whl", "requests_toolbelt-1.0.0-py2.py3-none-any.whl")]
    assert select_artifact(files, "requests", "auto").name == "requests-2.31.0-py3-none-any.whl"
    assert select_artifact(files, "requests-toolbelt", "wheel").name == "requests_toolbelt-1.0.0-py2.py3-none-any.whl"
    assert select_artifact(files, "requests", "sdist").name == "requests-2.31.0-py3-none-any.whl"  # falls back when the exact type is absent
    assert select_artifact(files, "flask", "auto") is None


def test_own_console_scripts_excludes_dependencies(tmp_path: Path):
    (tmp_path / "requests-2.31.0.dist-info").mkdir()
    (tmp_path / "requests-2.31.0.dist-info" / "entry_points.txt").write_text("[console_scripts]\nrequests-cli = requests.cli:main\n")
    (tmp_path / "idna-3.19.dist-info").mkdir()
    (tmp_path / "idna-3.19.dist-info" / "entry_points.txt").write_text("[console_scripts]\nidna = idna.cli:main\n")
    assert own_console_scripts(tmp_path, "requests") == ["requests-cli"]
    assert own_console_scripts(tmp_path, "flask") == []  # no dist-info -> no scripts, not an error


def test_own_console_scripts_no_console_scripts_section(tmp_path: Path):
    (tmp_path / "pkg-1.0.dist-info").mkdir()
    (tmp_path / "pkg-1.0.dist-info" / "entry_points.txt").write_text("[not_console_scripts]\nx = y:z\n")
    assert own_console_scripts(tmp_path, "pkg") == []


def test_build_install_stage_exempted_from_runtime_install_rule():
    exempt = NormalizedEvent(source="gvisor", category="process", type="process.exec", stage="install", data={"comm": "python", "args": "-m pip install ."})
    flagged = NormalizedEvent(source="gvisor", category="process", type="process.exec", stage="import", data={"comm": "python", "args": "-c import subprocess; subprocess.run(['pip','install','evil'])"})
    findings, _, _ = analyze([exempt, flagged])
    assert [f.rule_id for f in findings] == ["python.runtime_install"]
    assert findings[0].stage == "import"


def test_filesystem_diff(tmp_path: Path):
    before = FilesystemCollector().snapshot([tmp_path]); (tmp_path / "x").write_text("x"); after = FilesystemCollector().snapshot([tmp_path])
    assert after["%s" % (tmp_path / "x")]["size"] == 1
    assert len(FilesystemCollector().diff(before, after)["created"]) == 1


def test_gvisor_strace_collector_syscall_totals(tmp_path: Path):
    collector = GvisorStraceCollector(tmp_path)
    (tmp_path / "runsc.log.1.boot").write_text(
        "I0821 22:48:11.000000 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /tmp/x, O_RDONLY)\n"
        "I0821 22:48:11.000001 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /tmp/y, O_RDONLY)\n"
        "I0821 22:48:11.000002 100 strace.go:570] [   2:   2] python E read(0x3, 0x0, 0x100)\n"
    )
    collector.collect("install")
    assert collector.totals() == {"openat": 2, "read": 1}


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


def test_gvisor_strace_collector_chmod_evasion_sleep_fork(tmp_path: Path):
    collector = GvisorStraceCollector(tmp_path)
    (tmp_path / "runsc.log.1.boot").write_text(
        "I0821 22:48:11.000000 100 strace.go:570] [   2:   2] python E chmod(0x0 /tmp/payload, 0x1ed)\n"
        "I0821 22:48:11.000001 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /proc/cpuinfo, O_RDONLY)\n"
        "I0821 22:48:11.000002 100 strace.go:570] [   2:   2] python E nanosleep({Sec: 30, NSec: 0}, 0x0)\n"
        "I0821 22:48:11.000003 100 strace.go:570] [   2:   2] python X clone(0x1200011, 0x0, 0x0, 0x0, 0x0) = 42\n"
    )
    events = collector.collect("install")
    assert [e.type for e in events] == ["file.chmod", "evasion.probe", "process.sleep", "process.fork"]
    assert events[0].data["path"] == "/tmp/payload" and events[0].data["mode"] == "0o755"
    assert events[2].data["duration_s"] == 30
    assert events[3].data["child_pid"] == 42


def test_shannon_entropy():
    assert static_scan.shannon_entropy("aaaa") == 0.0
    assert static_scan.shannon_entropy("ab") == 1.0
    assert static_scan.shannon_entropy("") == 0.0


def test_levenshtein_typosquat_distance():
    assert registry._levenshtein("cat", "cat") == 0
    assert registry._levenshtein("cat", "bat") == 1
    assert registry._levenshtein("kitten", "sitting") == 3


def test_typosquat_check_uses_cache(tmp_path: Path):
    (tmp_path / "top-pypi-packages.json").write_text(json.dumps({"rows": [{"project": "requests"}, {"project": "numpy"}]}))
    exact = registry.typosquat_check("requests", tmp_path)
    assert exact == {"status": "success", "exact_match_in_top_packages": True, "candidate": None, "distance": 0}
    near = registry.typosquat_check("reqeusts", tmp_path)
    assert near["status"] == "success" and near["candidate"] == "requests" and near["distance"] <= 2
    far = registry.typosquat_check("some-totally-unrelated-name", tmp_path)
    assert far["candidate"] is None


def _client_hello_with_sni(hostname: str) -> bytes:
    name = hostname.encode()
    server_name = bytes([0]) + struct.pack(">H", len(name)) + name
    server_name_list = struct.pack(">H", len(server_name)) + server_name
    extensions = struct.pack(">HH", 0x0000, len(server_name_list)) + server_name_list
    body = (b"\x00" * 2 + b"\x00" * 32 + bytes([0]) + struct.pack(">H", 2) + b"\x00\x2f" + bytes([1]) + b"\x00" + struct.pack(">H", len(extensions)) + extensions)
    handshake = bytes([1]) + struct.pack(">I", len(body))[1:] + body
    return bytes([0x16]) + b"\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def test_parse_client_hello_sni():
    assert pcap_tls.parse_client_hello_sni(_client_hello_with_sni("evil.example.com")) == "evil.example.com"
    assert pcap_tls.parse_client_hello_sni(b"\x00garbage") is None
    assert pcap_tls.parse_client_hello_sni(b"") is None


def test_sni_mismatch_flags_unresolved_ip():
    records = [{"src": "172.17.0.2", "dst": "203.0.113.9", "dst_port": 443, "sni": "evil.example.com"}]
    answers = {"evil.example.com": ["198.51.100.1"]}
    mismatches = pcap_tls.sni_mismatches(records, answers)
    assert len(mismatches) == 1 and mismatches[0]["resolved_ips"] == ["198.51.100.1"]
    assert pcap_tls.sni_mismatches(records, {}) == []  # no DNS answer observed -> unverifiable, not a mismatch


def test_chmod_then_exec_correlation():
    events = [
        {"timestamp": "2026-01-01T00:00:00+00:00", "source": "gvisor", "category": "file", "type": "file.chmod", "stage": "install", "pid": 1, "data": {"path": "/tmp/payload", "mode": "0o755"}},
        {"timestamp": "2026-01-01T00:00:01+00:00", "source": "gvisor", "category": "process", "type": "process.exec", "stage": "install", "pid": 2, "data": {"exe": "/tmp/payload", "argv": ""}},
    ]
    result = signals.build_process_signals(events)
    assert len(result["chmod_then_exec"]) == 1
    assert result["chmod_then_exec"][0]["path"] == "/tmp/payload"


def test_declared_vs_loaded_modules():
    events = [
        {"timestamp": "2026-01-01T00:00:00+00:00", "source": "instrumentation", "category": "code", "type": "code.import", "stage": "import", "pid": None, "data": {"module": "requests"}},
        {"timestamp": "2026-01-01T00:00:01+00:00", "source": "instrumentation", "category": "code", "type": "code.import", "stage": "import", "pid": None, "data": {"module": "sneaky_backdoor"}},
    ]
    result = signals.build_filesystem_signals({"created": [], "modified": [], "deleted": []}, events, "/workspace", declared_deps={"requests"})
    assert result["declared_vs_loaded_modules"]["loaded_undeclared"] == ["sneaky_backdoor"]


def test_exec_drop_chmod_detects_octal_mode():
    """Regression: file.chmod mode is an oct() string ('0o755') which never contains 'x' — a literal
    substring check on it always returned an empty exec_drop_chmod list regardless of real chmod+x events."""
    created = [{"path": "/workspace/payload.sh", "mode": "0o755", "size": 10, "hash": "x"}]
    events = [{"timestamp": "2026-01-01T00:00:00+00:00", "source": "gvisor", "category": "file", "type": "file.chmod", "stage": "install", "pid": 1, "data": {"path": "/workspace/payload.sh", "mode": "0o755"}}]
    result = signals.build_filesystem_signals({"created": created, "modified": [], "deleted": []}, events, "/workspace", declared_deps=set())
    assert result["exec_drop_chmod"] == created


def test_outside_package_dir_ignores_own_infra_but_flags_payload():
    """Regression: workspace_root used to be a container-side path ('/workspace/site') compared against
    host-side snapshot paths, and a blanket '/tmp/' fallback masked everything since the whole analysis
    workspace lives under /tmp — so a payload dropped next to site/ was never flagged."""
    created = [
        {"path": "/tmp/pypi-dast-abc/site/pkg/__init__.py", "mode": "0o644", "size": 1, "hash": "x"},
        {"path": "/tmp/pypi-dast-abc/network.pcap", "mode": "0o644", "size": 1, "hash": "x"},
        {"path": "/tmp/pypi-dast-abc/requests-2.31.0-py3-none-any.whl", "mode": "0o644", "size": 1, "hash": "x"},
        {"path": "/tmp/pypi-dast-abc/payload.sh", "mode": "0o755", "size": 1, "hash": "x"},
    ]
    result = signals.build_filesystem_signals({"created": created, "modified": [], "deleted": []}, [], "/tmp/pypi-dast-abc", declared_deps=set())
    assert [e["path"] for e in result["outside_package_dir"]] == ["/tmp/pypi-dast-abc/payload.sh"]


def test_scan_credential_patterns_flags_known_shapes():
    assert sinkhole.scan_credential_patterns(b"", b'{"key": "AKIAABCDEFGHIJKLMNOP"}')[0]["pattern"] == "aws_access_key_id"
    assert sinkhole.scan_credential_patterns(b"", b"-----BEGIN RSA PRIVATE KEY-----\nMIIB...")[0]["pattern"] == "private_key_pem"
    assert sinkhole.scan_credential_patterns(b"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", b"")[0]["pattern"] == "bearer_token"
    assert sinkhole.scan_credential_patterns(b"", b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY")[0]["pattern"] == "secret_like_assignment"
    assert sinkhole.scan_credential_patterns(b"", b"just a normal request body with nothing sensitive") == []


def test_build_dns_a_response_resolves_any_query_to_sinkhole_ip():
    query = bytes.fromhex("aaaa01000001000000000000") + b"\x07example\x03com\x00" + bytes.fromhex("00010001")
    response = sinkhole.build_dns_a_response(query, "172.17.0.1")
    assert response is not None
    assert response[:2] == b"\xaa\xaa"  # echoes the query's transaction id
    assert response.endswith(socket.inet_aton("172.17.0.1"))
    assert sinkhole.build_dns_a_response(b"too short", "172.17.0.1") is None


def test_build_network_signals_http_body_patterns_reflect_sinkhole_state():
    without_sinkhole = signals.build_network_signals([], [], [], [], [], sinkhole_records=None)
    assert without_sinkhole["http_body_credential_patterns"]["status"] == "not_implemented"
    captures = [{"host": "evil.example.com", "credential_matches": [{"pattern": "aws_access_key_id", "preview": "AKIA..."}]}]
    with_sinkhole = signals.build_network_signals([], [], [], [], [], sinkhole_records=captures)
    assert with_sinkhole["http_body_credential_patterns"] == {"status": "success", "captures": captures}


@pytest.mark.skipif(shutil.which("openssl") is None, reason="requires the openssl CLI")
def test_sinkhole_issues_leaf_cert_signed_by_its_own_ca(tmp_path: Path):
    sh = sinkhole.Sinkhole(tmp_path)
    assert sh._generate_ca() is True
    assert sh.ca_pem.exists() and sh.ca_pem.stat().st_size > 0
    ctx = sh._leaf_context("evil.example.com")
    assert isinstance(ctx, __import__("ssl").SSLContext)
    assert (tmp_path / "_leaf-evil.example.com.pem").exists()


def test_gvisor_strace_flags_write_outside_site_but_not_own_infra(tmp_path: Path):
    """Regression: a dropper that writes+chmod+x's+execs+deletes itself never appears in the before/after
    fs-diff snapshot — only this realtime syscall view catches it. Must stay silent for our own
    site/build/instrumentation writes so it doesn't drown the report with routine install noise."""
    collector = GvisorStraceCollector(tmp_path)
    (tmp_path / "runsc.log.1.boot").write_text(
        "I0821 22:48:11.000000 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /workspace/payload.sh, O_WRONLY|O_CREAT)\n"
        "I0821 22:48:11.000001 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /workspace/.bashrc, O_WRONLY|O_CREAT)\n"
        "I0821 22:48:11.000002 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /workspace/site/pkg/mod.py, O_WRONLY|O_CREAT)\n"
        "I0821 22:48:11.000003 100 strace.go:570] [   2:   2] python E openat(AT_FDCWD /, 0x0 /workspace/_env-access.log, O_WRONLY|O_CREAT)\n"
    )
    events = collector.collect("install")
    outside_site = [e for e in events if e.type == "file.write_outside_site"]
    assert {e.data["path"]: e.data["kind"] for e in outside_site} == {"/workspace/payload.sh": "outside_site", "/workspace/.bashrc": "autorun"}


def test_outside_package_dir_catches_self_deleting_dropper():
    """Path exists only via the realtime syscall event, never in fs-diff (it deleted itself) — must still
    surface, since the whole point is catching what fs-diff's before/after diff structurally can't see."""
    events = [{"timestamp": "t", "source": "gvisor", "category": "file", "type": "file.write_outside_site", "stage": "install", "pid": 1, "data": {"path": "/workspace/payload.sh", "kind": "outside_site"}}]
    result = signals.build_filesystem_signals({"created": [], "modified": [], "deleted": []}, events, "/workspace", declared_deps=set())
    assert result["outside_package_dir"] == [{"path": "/workspace/payload.sh", "stage": "install", "note": "seen only via syscall trace — not present in the before/after snapshot, likely deleted before it"}]


def test_exfil_channel_matches_checks_sinkhole_hosts_too():
    """Regression: a hardcoded-IP exfil target that skips DNS entirely never appears in dns_domains, but
    the sinkhole still observed the Host it connected as — that must count as a match too."""
    result = signals.build_network_signals([], [], [], [], [], sinkhole_records=[{"host": "evil.webhook.site", "dst_port": 443}])
    assert result["exfil_channel_matches"] == ["evil.webhook.site"]


def test_sinkhole_records_feed_env_bulk_access_correlation():
    """Regression: env->network correlation only checked gvisor's network.connect, never netsim/sinkhole
    captures — a bulk os.environ scan followed by a sinkhole-observed exfil POST went uncorrelated."""
    env_log = [{"event": "bulk_iteration", "via": "items", "timestamp": 1000.0, "stage": "import"}]
    sinkhole_records = [{"host": "evil.example.com", "timestamp": "1970-01-01T00:16:41+00:00", "dst_port": 443}]  # 1 second after
    events = signals.build_events_jsonl([], {}, {}, [], [], env_log, [], [], "1970-01-01T00:16:42+00:00", sinkhole_records)
    result = signals.build_env_signals(events)
    assert len(result["network_after_bulk_access"]) == 1


def test_sinkhole_degrades_honestly_without_openssl(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(sinkhole.shutil, "which", lambda _: None)
    sh = sinkhole.Sinkhole(tmp_path)
    sh.start()
    assert sh.active is False
    assert "openssl not installed" in sh.status
    assert sh.to_netsim_json() == {"status": "unavailable", "reason": sh.status}
    sh.stop()  # must be a no-op, not raise, when start() never actually came up
