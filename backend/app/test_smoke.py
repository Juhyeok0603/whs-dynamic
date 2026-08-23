import json
import shutil
import socket
import struct
import zipfile
from pathlib import Path
import pytest
from .collectors import EbpfCollector, FilesystemCollector, GvisorStraceCollector, PcapCollector
from .analyzer import analyze
from .package import ensure_build_backends_cached, guess_package_name, own_console_scripts, read_package_metadata, select_artifact
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


def test_guess_package_name_from_uploaded_filename():
    """Fallback naming for uploaded artifacts with no usable METADATA/PKG-INFO (a real malicious sample
    often won't have proper packaging metadata) — derived the same way select_artifact already assumes
    PyPI-style filenames are shaped."""
    assert guess_package_name("evil_pkg-1.0.0-py3-none-any.whl") == "evil_pkg"
    assert guess_package_name("malicious-sample-2.3.tar.gz") == "malicious-sample"
    assert guess_package_name("no-version-marker-here.zip") == "no-version-marker-here"
    assert guess_package_name("noext") == "noext"


def test_read_package_metadata_finds_pkg_info_in_zip_sdist(tmp_path: Path):
    """Regression: an sdist packaged as .zip (valid but uncommon — most use .tar.gz) has PKG-INFO, not
    *.dist-info/METADATA. The zip branch only checked the latter, so real name/version silently fell back
    to the empty stub for this shape — encountered on an actual uploaded sample."""
    artifact = tmp_path / "weird-sdist-1.0.zip"
    with zipfile.ZipFile(artifact, "w") as zf:
        zf.writestr("weird-sdist-1.0/PKG-INFO", "Metadata-Version: 2.1\nName: weird-sdist\nVersion: 1.0\n")
    metadata = read_package_metadata(artifact)
    assert metadata["raw_available"] is True
    assert metadata["name"] == "weird-sdist"
    assert metadata["version"] == "1.0"


def test_ensure_build_backends_cached_skips_download_when_already_populated(tmp_path: Path, monkeypatch):
    """The build-backend cache is meant to be filled once and reused across analyses — a populated cache_dir
    must short-circuit before ever shelling out to pip download again."""
    (tmp_path / "setuptools-70.0.0-py3-none-any.whl").write_bytes(b"fake wheel")
    called = []
    monkeypatch.setattr("backend.app.package.subprocess.run", lambda *a, **k: called.append(a))
    result = ensure_build_backends_cached(tmp_path)
    assert not called  # never shelled out — cache already had something in it
    assert [p.name for p in result] == ["setuptools-70.0.0-py3-none-any.whl"]


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
    """Regression: credential-pattern scanning used to happen inside sinkhole.py at capture time (baked
    into netsim.json itself); it now happens here at signal-extraction time, off the raw headers/body
    previews — netsim.json stays a pure, unopinionated record (matches the raw-vs-derived split used
    everywhere else in this pipeline, and the npm sibling's own netsim.json/extractor split)."""
    without_sinkhole = signals.build_network_signals([], [], [], [], [], sinkhole_records=None)
    assert without_sinkhole["http_body_credential_patterns"]["status"] == "not_implemented"
    captures = [{"host": "evil.example.com", "headers_preview": "", "body_preview": '{"key": "AKIAABCDEFGHIJKLMNOP"}'}]
    with_sinkhole = signals.build_network_signals([], [], [], [], [], sinkhole_records=captures)
    result_captures = with_sinkhole["http_body_credential_patterns"]["captures"]
    assert len(result_captures) == 1
    assert result_captures[0]["credential_matches"][0]["pattern"] == "aws_access_key_id"
    assert result_captures[0]["host"] == "evil.example.com"  # original fields preserved alongside the new one


def test_decode_body_preview_hex_fallback_for_non_utf8():
    assert sinkhole._decode_body_preview(b"hello world") == "hello world"
    assert sinkhole._decode_body_preview(bytes([0xFF, 0xFE])) == "fffe"  # lossless, unlike errors="replace"


def test_safe_host_rejects_injection_characters():
    """Regression: the raw SNI (fully attacker-controlled) used to go straight into an openssl -subj
    argument and an extfile's content — a newline or '/' in it could inject extra DN fields or extension
    directives. Anything outside a plain DNS-label charset must be replaced before touching openssl."""
    assert sinkhole._safe_host("evil.example.com") == "evil.example.com"
    assert sinkhole._safe_host("evil.com\nbasicConstraints=critical,CA:TRUE") == "invalid-sni.invalid"
    assert sinkhole._safe_host("evil.com/O=Fake") == "invalid-sni.invalid"
    assert sinkhole._safe_host(None) == "invalid-sni.invalid"
    assert sinkhole._safe_host("") == "invalid-sni.invalid"


def test_build_dns_a_response_returns_nodata_for_non_a_queries():
    """Regression: qtype was never checked, so an AAAA query got an A-record answer stuffed into a
    mismatched response — some stub resolvers treat that as a hard failure for the whole lookup."""
    aaaa_query = bytes.fromhex("bbbb01000001000000000000") + b"\x07example\x03com\x00" + bytes.fromhex("001c0001")  # qtype=28 (AAAA)
    response = sinkhole.build_dns_a_response(aaaa_query, "172.17.0.1")
    assert response is not None
    header = response[:12]
    ancount = struct.unpack(">H", header[6:8])[0]
    assert ancount == 0
    assert not response.endswith(socket.inet_aton("172.17.0.1"))


@pytest.mark.skipif(shutil.which("openssl") is None, reason="requires the openssl CLI")
def test_sinkhole_issues_leaf_cert_signed_by_its_own_ca(tmp_path: Path):
    sh = sinkhole.Sinkhole(tmp_path, "test-analysis-id")
    assert sh._generate_ca() is True
    assert sh.ca_pem.exists() and sh.ca_pem.stat().st_size > 0
    ctx = sh._leaf_context("evil.example.com")
    assert isinstance(ctx, __import__("ssl").SSLContext)
    assert (tmp_path / "_leaf-evil.example.com.pem").exists()


def test_sinkhole_derives_docker_network_and_nat_chain_names_from_analysis_id():
    sh = sinkhole.Sinkhole(Path("/tmp/whatever"), "AbCdEf12-3456-7890")
    assert sh.docker_network == "dast-sh-abcdef12"
    assert sh._nat_chain == "DAST_SH_ABCDEF12"


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
    sh = sinkhole.Sinkhole(tmp_path, "test-analysis-id")
    sh.start()
    assert sh.active is False
    assert "openssl not installed" in sh.status
    assert sh.to_netsim_json() == {"status": "unavailable", "reason": sh.status}
    sh.stop()  # must be a no-op, not raise, when start() never actually came up


def test_process_tree_depth_follows_parent_chain():
    """Regression: process_tree had no depth field at all — pid/exe/ppid only. A grandchild process
    (dropper -> shell -> payload) should come out at depth 2, not just flat pid/ppid pairs."""
    events = [
        {"timestamp": "t0", "source": "gvisor", "category": "process", "type": "process.exec", "stage": "install", "pid": 1, "data": {"exe": "python"}},
        {"timestamp": "t1", "source": "gvisor", "category": "process", "type": "process.fork", "stage": "install", "pid": 1, "data": {"child_pid": 2}},
        {"timestamp": "t2", "source": "gvisor", "category": "process", "type": "process.exec", "stage": "install", "pid": 2, "data": {"exe": "sh"}},
        {"timestamp": "t3", "source": "gvisor", "category": "process", "type": "process.fork", "stage": "install", "pid": 2, "data": {"child_pid": 3}},
        {"timestamp": "t4", "source": "gvisor", "category": "process", "type": "process.exec", "stage": "install", "pid": 3, "data": {"exe": "payload"}},
    ]
    tree = {n["pid"]: n for n in signals.build_process_signals(events)["process_tree"]}
    assert tree[1]["depth"] == 0
    assert tree[2]["depth"] == 1
    assert tree[3]["depth"] == 2


def test_docker_command_network_override_ignores_none_bridge_mapping():
    """sinkhole needs its own per-analysis docker network, not the default 'bridge' this function would
    otherwise pick for any non-disabled/restricted mode."""
    from . import sandbox
    cmd = sandbox.docker_command(Path("/tmp/x"), ["echo", "hi"], "sinkhole", docker_network="dast-sh-abcdef12")
    assert cmd[cmd.index("--network") + 1] == "dast-sh-abcdef12"


def test_ip_hardcode_bypass_attempts_flags_ip_never_seen_in_dns_answer():
    """Regression: gvisor already parses connect()'s raw destination IP, but nothing compared it against
    DNS answers — a package that hardcodes an exfil IP and skips DNS entirely went undetected."""
    events = [
        {"timestamp": "t0", "source": "gvisor", "category": "network", "type": "network.connect", "stage": "install", "pid": 1, "data": {"dst_ip": "172.17.0.1"}},  # matches a DNS answer
        {"timestamp": "t1", "source": "gvisor", "category": "network", "type": "network.connect", "stage": "install", "pid": 1, "data": {"dst_ip": "203.0.113.9"}},  # never resolved
    ]
    dns_answers = {"evil.example.com": ["172.17.0.1"]}
    result = signals.build_network_signals(events, [], [], [], [], dns_answers=dns_answers)
    assert result["ip_hardcode_bypass_attempts"] == [{"stage": "install", "dst_ip": "203.0.113.9"}]
