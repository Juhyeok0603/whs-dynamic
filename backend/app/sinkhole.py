import re
import shutil
import socket
import ssl
import struct
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_OPENSSL_TIMEOUT = 15
_CERT_DAYS = "2"  # ephemeral: regenerated every analysis, discarded with the workspace — never a lasting trust anchor
_MAX_REQUEST_BYTES = 65536
_ACCEPT_POLL_S = 0.5
_CONN_TIMEOUT_S = 5

# Body/header patterns worth flagging as "this looks like it's exfiltrating a secret" — deliberately
# simple substring/regex matching (no ML), mirrors the plain-heuristic style used throughout signals.py.
_CRED_PATTERNS = {
    "aws_access_key_id": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private_key_pem": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "bearer_token": re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9\-_.]{20,}", re.IGNORECASE),
    "secret_like_assignment": re.compile(rb"\b[A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]*\s*[:=]\s*[\"']?[^\s\"'&]{6,}", re.IGNORECASE),
}


def scan_credential_patterns(head: bytes, body: bytes) -> list[dict[str, str]]:
    """Pure function (no sockets/openssl involved) so this is unit-testable on its own."""
    blob = head + b"\n" + body
    matches = []
    for name, pattern in _CRED_PATTERNS.items():
        found = pattern.search(blob)
        if found:
            matches.append({"pattern": name, "preview": found.group(0)[:80].decode("utf-8", errors="replace")})
    return matches


def build_dns_a_response(query: bytes, answer_ip: str) -> bytes | None:
    """Builds a DNS response answering every query with a single A record pointing at answer_ip,
    regardless of what name was asked — the sinkhole never performs real resolution. Returns None for a
    malformed query rather than raising, since this reads untrusted bytes off the wire."""
    if len(query) < 12:
        return None
    txid = query[:2]
    qdcount = struct.unpack(">H", query[4:6])[0]
    if qdcount < 1:
        return None
    pos = 12
    try:
        while query[pos] != 0:
            pos += 1 + query[pos]
        pos += 1 + 4  # null label terminator + qtype(2) + qclass(2)
    except IndexError:
        return None
    question = query[12:pos]
    header = txid + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(answer_ip)
    return header + question + answer


def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]", "_", name)[:100]


class Sinkhole:
    """Forces every outbound connection from the sandboxed container into a local TLS-terminating
    listener (regardless of whether the analyzed code respects HTTP_PROXY or uses raw sockets), by
    pointing the container's DNS at us and always answering with our own IP. Never actually relays to
    the real destination — this is a sinkhole, not a forwarding proxy, so nothing the analyzed code does
    can actually reach the internet through it. Follows the same start()/stop()/status lifecycle as the
    other collectors (PcapCollector, EbpfCollector)."""

    name = "sinkhole"

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.ca_key = workspace / "mitm-ca.key"
        self.ca_pem = workspace / "mitm-ca.pem"
        self.bind_ip = "127.0.0.1"
        self.active = False
        self.status = "not started"
        self._leaf_cache: dict[str, ssl.SSLContext] = {}
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._captures: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._stop_flag = threading.Event()

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=_OPENSSL_TIMEOUT)

    def _generate_ca(self) -> bool:
        result = self._run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(self.ca_key), "-out", str(self.ca_pem), "-days", _CERT_DAYS, "-subj", "/CN=pypi-dast-mitm-ca"])
        return result.returncode == 0 and self.ca_pem.exists()

    def _bridge_gateway_ip(self) -> str:
        result = subprocess.run(["docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}"], capture_output=True, text=True, timeout=10)
        gateway = result.stdout.strip()
        return gateway if result.returncode == 0 and gateway else "172.17.0.1"  # docker's conventional default bridge gateway

    def _leaf_context(self, hostname: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._leaf_cache.get(hostname)
            if ctx is not None:
                return ctx
            safe = _safe_filename(hostname)
            leaf_key, leaf_csr, leaf_pem, ext_file = (self.workspace / f"_leaf-{safe}{suffix}" for suffix in (".key", ".csr", ".pem", ".ext"))
            ext_file.write_text(f"subjectAltName=DNS:{hostname}\n", encoding="utf-8")
            self._run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key), "-out", str(leaf_csr), "-subj", f"/CN={hostname}"])
            self._run(["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(self.ca_pem), "-CAkey", str(self.ca_key), "-CAcreateserial", "-out", str(leaf_pem), "-days", _CERT_DAYS, "-extfile", str(ext_file)])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(leaf_pem), keyfile=str(leaf_key))
            self._leaf_cache[hostname] = ctx
            return ctx

    def _sni_callback(self, sslsock: ssl.SSLSocket, server_name: str | None, ssl_context: ssl.SSLContext) -> None:
        hostname = server_name or "unknown-no-sni"
        sslsock._sinkhole_host = hostname  # stashed per-connection; safe (sslsock is this connection's own instance)
        try:
            sslsock.context = self._leaf_context(hostname)
        except (OSError, ssl.SSLError):
            pass  # leaf issuance failed -> handshake will fail on an unconfigured context; connection just drops

    def start(self) -> None:
        if shutil.which("openssl") is None:
            self.status = "openssl not installed"
            return
        if not self._generate_ca():
            self.status = "CA generation failed (openssl req -x509 did not produce a cert)"
            return
        self.bind_ip = self._bridge_gateway_ip()
        try:
            dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_sock.bind((self.bind_ip, 53))
            http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            http_sock.bind((self.bind_ip, 80))
            http_sock.listen(16)
            https_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            https_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            https_sock.bind((self.bind_ip, 443))
            https_sock.listen(16)
        except PermissionError:
            self.status = "permission denied: setcap cap_net_bind_service+ep on python3 (see scripts/setup_ubuntu.sh)"
            return
        except OSError as exc:
            self.status = f"bind failed: {exc}"
            return
        base_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        base_ctx.sni_callback = self._sni_callback
        self._sockets = [dns_sock, http_sock, https_sock]
        self._threads = [
            threading.Thread(target=self._serve_dns, args=(dns_sock,), daemon=True),
            threading.Thread(target=self._serve_plain, args=(http_sock,), daemon=True),
            threading.Thread(target=self._serve_tls, args=(https_sock, base_ctx), daemon=True),
        ]
        for t in self._threads:
            t.start()
        self.active = True
        self.status = f"capturing (bind {self.bind_ip})"

    def _serve_dns(self, sock: socket.socket) -> None:
        sock.settimeout(_ACCEPT_POLL_S)
        while not self._stop_flag.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            response = build_dns_a_response(data, self.bind_ip)
            if response:
                try:
                    sock.sendto(response, addr)
                except OSError:
                    pass

    def _serve_plain(self, listen_sock: socket.socket) -> None:
        listen_sock.settimeout(_ACCEPT_POLL_S)
        while not self._stop_flag.is_set():
            try:
                conn, _ = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_http, args=(conn, "unknown-http", 80), daemon=True).start()

    def _serve_tls(self, listen_sock: socket.socket, base_ctx: ssl.SSLContext) -> None:
        listen_sock.settimeout(_ACCEPT_POLL_S)
        while not self._stop_flag.is_set():
            try:
                conn, _ = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._accept_tls, args=(conn, base_ctx), daemon=True).start()

    def _accept_tls(self, conn: socket.socket, base_ctx: ssl.SSLContext) -> None:
        try:
            conn.settimeout(_CONN_TIMEOUT_S)
            tls_conn = base_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            conn.close()
            return
        hostname = getattr(tls_conn, "_sinkhole_host", "unknown-no-sni")
        self._handle_http(tls_conn, hostname, 443)

    def _handle_http(self, sock: socket.socket, hostname: str, dst_port: int) -> None:
        try:
            sock.settimeout(_CONN_TIMEOUT_S)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < _MAX_REQUEST_BYTES:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            headers_text = head.decode("latin-1", errors="replace")
            content_length = 0
            match = re.search(r"(?im)^content-length:\s*(\d+)", headers_text)
            if match:
                content_length = min(int(match.group(1)), _MAX_REQUEST_BYTES)
            body = rest
            while len(body) < content_length:
                chunk = sock.recv(min(4096, content_length - len(body)))
                if not chunk:
                    break
                body += chunk
            request_line = headers_text.splitlines()[0] if headers_text else ""
            method, _, rest_of_line = request_line.partition(" ")
            path = rest_of_line.split(" ")[0] if rest_of_line else None
            matches = scan_credential_patterns(head, body)
            with self._lock:
                self._captures.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": hostname,
                    "dst_port": dst_port,
                    "method": method or None,
                    "path": path,
                    "headers_preview": headers_text[:1000],
                    "body_preview": body[:500].decode("utf-8", errors="replace"),
                    "credential_matches": matches,
                })
            try:
                sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        except (OSError, ssl.SSLError, socket.timeout):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def stop(self) -> None:
        if not self.active:
            return
        self._stop_flag.set()
        for t in self._threads:
            t.join(timeout=2)
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
        # Matches the "success (...)" convention every other collector's status uses once it's done
        # (PcapCollector, EbpfCollector) — the dashboard's status chip greys/reds anything that doesn't
        # contain one of those success-ish words, so leaving this at "capturing (bind ...)" forever would
        # show a completed, successful sinkhole run as a red/failed chip.
        self.status = f"success ({len(self._captures)} HTTP request(s) captured, bind {self.bind_ip})"

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._captures)

    def to_netsim_json(self) -> dict[str, Any]:
        if not self.active:
            return {"status": "unavailable", "reason": self.status}
        return {"status": "success", "bind_ip": self.bind_ip, "capture_count": len(self._captures), "captures": self.records()}
