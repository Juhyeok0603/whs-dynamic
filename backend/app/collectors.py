from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import hashlib
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Any
from .schemas import NormalizedEvent


class Collector:
    name = "collector"
    def start(self) -> None: pass
    def stop(self) -> None: pass
    def collect(self) -> list[NormalizedEvent]: return []


class FilesystemCollector(Collector):
    name = "filesystem"
    def snapshot(self, roots: list[Path]) -> dict[str, dict[str, Any]]:
        result = {}
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if path.is_file():
                    try:
                        result[str(path)] = {"size": path.stat().st_size, "hash": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": oct(path.stat().st_mode & 0o777)}
                    except OSError:
                        pass
        return result

    def diff(self, before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[Any]]:
        created = [dict(path=p, **after[p]) for p in after.keys() - before.keys()]
        deleted = [dict(path=p, **before[p]) for p in before.keys() - after.keys()]
        modified = [dict(path=p, before=before[p], after=after[p]) for p in after.keys() & before.keys() if after[p] != before[p]]
        return {"created": created, "modified": modified, "deleted": deleted}


class RuntimeCollector(Collector):
    name = "runtime"
    def event(self, stage: str, event_type: str, data: dict[str, Any], category: str = "runtime") -> NormalizedEvent:
        return NormalizedEvent(source=self.name, category=category, type=event_type, stage=stage, data=data)


# runsc --strace entry line: "... strace.go:NNN] [ pid: tid] comm E syscall(args"
_STRACE_LINE = re.compile(r"strace\.go:\d+\]\s+\[\s*(\d+):\s*\d+\]\s+(\S+)\s+E\s+(\w+)\((.*)")
# execve(pathname, argv[...], envp[...]) — pull out just the exec target and argv, since envp (e.g. the
# official Python image's PYTHON_SHA256=... env var) would otherwise pollute any substring match on the raw args.
_EXECVE_PATH = re.compile(r"(/[^\s,]+)")
_EXECVE_ARGV = re.compile(r"\[(.*?)\]")
_SENSITIVE = (".aws", ".ssh", ".netrc", "/etc/passwd", "/etc/shadow")
_PRIVILEGE = ("setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "capset")
_ESCAPE = ("ptrace", "mount", "umount2", "unshare", "setns", "pivot_root", "chroot", "init_module", "finit_module", "bpf", "keyctl", "add_key")
_DNS_PORT = re.compile(r"Port:\s*53\b")


class GvisorStraceCollector(Collector):
    """Parses runsc debug/strace logs written by the '<runtime>-trace' Docker runtime into normalized events."""
    name = "gvisor"

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.seen: set[str] = set()
        self.syscall_counts: Counter = Counter()  # every syscall seen, not just the ones turned into typed events
        self.mark()

    def available(self) -> bool:
        return self.log_dir.is_dir()

    def mark(self) -> None:
        self.seen = {p.name for p in self.log_dir.glob("*")} if self.available() else set()

    def totals(self) -> dict[str, int]:
        return dict(self.syscall_counts)

    def collect(self, stage: str, limit: int = 200) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for path in sorted(self.log_dir.glob("*")) if self.available() else []:
            if path.name in self.seen:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                match = _STRACE_LINE.search(line)
                if not match:
                    continue
                pid, comm, syscall, args = int(match.group(1)), match.group(2), match.group(3), match.group(4)[:512]
                self.syscall_counts[syscall] += 1
                if syscall in ("execve", "execveat"):
                    path_match = _EXECVE_PATH.search(args)
                    argv_match = _EXECVE_ARGV.search(args)
                    exe = path_match.group(1) if path_match else comm
                    argv = argv_match.group(1) if argv_match else ""
                    events.append(NormalizedEvent(source=self.name, category="process", type="process.exec", stage=stage, pid=pid, data={"comm": comm, "exe": exe, "argv": argv, "args": args}))
                elif syscall == "connect":
                    events.append(NormalizedEvent(source=self.name, category="network", type="network.connect", stage=stage, pid=pid, data={"comm": comm, "args": args}))
                    if _DNS_PORT.search(args):
                        events.append(NormalizedEvent(source=self.name, category="dns", type="dns.query", stage=stage, pid=pid, data={"comm": comm, "args": args}))
                elif syscall in ("sendto", "sendmsg") and _DNS_PORT.search(args):
                    events.append(NormalizedEvent(source=self.name, category="dns", type="dns.query", stage=stage, pid=pid, data={"comm": comm, "args": args}))
                elif syscall in _PRIVILEGE:
                    events.append(NormalizedEvent(source=self.name, category="privilege", type="privilege.change", stage=stage, pid=pid, data={"comm": comm, "syscall": syscall, "args": args}))
                elif syscall in _ESCAPE:
                    events.append(NormalizedEvent(source=self.name, category="privilege", type="sandbox.escape_syscall", stage=stage, pid=pid, data={"comm": comm, "syscall": syscall, "args": args}))
                # ponytail: opens are only kept for sensitive paths; full file telemetry would drown the report
                elif syscall in ("open", "openat") and any(s in args for s in _SENSITIVE):
                    events.append(NormalizedEvent(source=self.name, category="file", type="file.read", stage=stage, pid=pid, data={"comm": comm, "path": args}))
                if len(events) >= limit:
                    break
            if len(events) >= limit:
                break
        self.mark()
        return events


class HostSamplerCollector(Collector):
    """Background thread sampling /proc (runsc processes) and docker cgroups while sandboxed stages run."""
    name = "host"

    def __init__(self, interval: float = 0.5):
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.proc_samples = 0
        self.proc_max = {"processes": 0, "rss_kb": 0}
        self.proc_series: list[dict[str, Any]] = []
        self.cgroup_samples = 0
        self.cgroup_max = {"memory_bytes": 0, "pids": 0, "cpu_usec": 0}
        self.cgroup_series: list[dict[str, Any]] = []

    def proc_available(self) -> bool: return Path("/proc").is_dir()
    def cgroup_available(self) -> bool: return Path("/sys/fs/cgroup").is_dir()

    def start(self) -> None:
        if not (self.proc_available() or self.cgroup_available()):
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            if self.proc_available():
                self._sample_proc()
            if self.cgroup_available():
                self._sample_cgroup()

    def _sample_proc(self) -> None:
        count = rss = 0
        for p in Path("/proc").iterdir():
            if not p.name.isdigit():
                continue
            try:
                if b"runsc" not in (p / "cmdline").read_bytes():
                    continue
                count += 1
                for line in (p / "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        rss += int(line.split()[1]); break
            except OSError:
                continue
        if count:
            self.proc_samples += 1
            self.proc_max = {"processes": max(self.proc_max["processes"], count), "rss_kb": max(self.proc_max["rss_kb"], rss)}
            self.proc_series.append({"t": datetime.now(timezone.utc).isoformat(), "processes": count, "rss_kb": rss})

    def _sample_cgroup(self) -> None:
        # ponytail: reads every docker container cgroup — assumes the analysis VM only runs our sandbox; use --cidfile for exact matching
        scopes = list(Path("/sys/fs/cgroup/system.slice").glob("docker-*.scope")) + list(Path("/sys/fs/cgroup/docker").glob("*/"))
        mem = pids = cpu = 0
        for scope in scopes:
            try:
                mem += int((scope / "memory.current").read_text())
                pids += int((scope / "pids.current").read_text())
                for line in (scope / "cpu.stat").read_text().splitlines():
                    if line.startswith("usage_usec"):
                        cpu += int(line.split()[1]); break
            except (OSError, ValueError):
                continue
        if scopes:
            self.cgroup_samples += 1
            self.cgroup_max = {"memory_bytes": max(self.cgroup_max["memory_bytes"], mem), "pids": max(self.cgroup_max["pids"], pids), "cpu_usec": max(self.cgroup_max["cpu_usec"], cpu)}
            self.cgroup_series.append({"t": datetime.now(timezone.utc).isoformat(), "memory_bytes": mem, "pids": pids, "cpu_usec": cpu})

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def usage(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.proc_samples:
            result["proc"] = {"samples": self.proc_samples, **self.proc_max, "series": self.proc_series}
        if self.cgroup_samples:
            result["cgroup"] = {"samples": self.cgroup_samples, **self.cgroup_max, "series": self.cgroup_series}
        return result


class PcapCollector(Collector):
    """Captures bridge traffic with tcpdump during sandboxed stages. Only meaningful with --network full."""
    name = "pcap"
    _LINE = re.compile(r"IP6?\s+(\S+?)\.(\d+)\s+>\s+(\S+?)\.(\d+):")
    # tcpdump's default (non -q) decoder prints DNS queries like "... : 1234+ A? example.com. (33)".
    # ponytail: best-effort text-format parsing against tcpdump's default decoder; may need adjustment across tcpdump versions.
    _DNS_QUERY = re.compile(r"\s\d+\+?\s+\w+\?\s+(\S+?)\.\s")

    def __init__(self, network: str, pcap_path: Path, interface: str = "docker0"):
        self.network = network
        self.interface = interface
        self.pcap_path = pcap_path
        self.proc: subprocess.Popen | None = None
        self.flows: dict[tuple[str, str, int], int] = {}
        self.dns_names: set[str] = set()
        self.status = "disabled (network none)" if network in ("disabled", "restricted") else "not started"

    @classmethod
    def parse_line(cls, line: str) -> tuple[str, str, int] | None:
        match = cls._LINE.search(line)
        return (match.group(1), match.group(3), int(match.group(4))) if match else None

    @classmethod
    def parse_dns_name(cls, line: str) -> str | None:
        match = cls._DNS_QUERY.search(line)
        return match.group(1) if match else None

    def start(self) -> None:
        if self.network in ("disabled", "restricted"):
            return
        if shutil.which("tcpdump") is None:
            self.status = "tcpdump not installed"
            return
        try:
            # Written to a file (not piped live) so the raw capture survives as an artifact; decoded for
            # flow/DNS parsing afterward via a second "tcpdump -r" read pass in stop().
            self.proc = subprocess.Popen(["tcpdump", "-i", self.interface, "-n", "-w", str(self.pcap_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            self.status = "capturing"
        except OSError as exc:
            self.status = f"failed to start: {exc}"

    def stop(self) -> None:
        if not self.proc:
            return
        self.proc.terminate()
        try:
            _, err = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        if "not permitted" in err.lower() or "permission" in err.lower():
            self.status = "permission denied: setcap cap_net_raw,cap_net_admin+ep $(which tcpdump)"
            return
        if not self.pcap_path.exists() or self.pcap_path.stat().st_size == 0:
            self.status = "success (0 packets)"
            return
        decode = subprocess.run(["tcpdump", "-r", str(self.pcap_path), "-n"], capture_output=True, text=True)
        for line in decode.stdout.splitlines():
            parsed = self.parse_line(line)
            if parsed:
                self.flows[parsed] = self.flows.get(parsed, 0) + 1
            name = self.parse_dns_name(line)
            if name:
                self.dns_names.add(name.rstrip("."))
        self.status = f"success ({sum(self.flows.values())} packets, {len(self.flows)} flows, saved to {self.pcap_path.name})"

    def summary(self, limit: int = 100) -> list[dict[str, Any]]:
        ranked = sorted(self.flows.items(), key=lambda kv: -kv[1])[:limit]
        return [{"src": src, "dst": dst, "dst_port": port, "packets": count} for (src, dst, port), count in ranked]

    def domains(self) -> list[str]:
        return sorted(self.dns_names)


class EbpfCollector(Collector):
    """Host-boundary observer via bpftrace (needs sudo NOPASSWD). Cross-checks gVisor telemetry; never feeds the analyzer."""
    name = "ebpf"
    _SCRIPT = 'tracepoint:sched:sched_process_exec { printf("EXEC pid=%d comm=%s file=%s\\n", pid, comm, str(args->filename)); } kprobe:tcp_connect { printf("CONN pid=%d comm=%s\\n", pid, comm); }'
    _PARSE = re.compile(r"^(EXEC|CONN) pid=(\d+) comm=(\S+)(?: file=(.*))?$")
    _IGNORE = ("docker", "dockerd", "containerd", "runsc", "systemd", "sudo", "bpftrace", "tcpdump", "pkill", "sh")

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.observations: list[dict[str, Any]] = []
        self.status = "not started"

    @classmethod
    def parse_line(cls, line: str) -> dict[str, Any] | None:
        match = cls._PARSE.match(line.strip())
        if not match or match.group(3) in cls._IGNORE:
            return None
        kind, pid, comm, file = match.groups()
        event = {"type": "process.exec" if kind == "EXEC" else "network.connect", "pid": int(pid), "comm": comm}
        if file:
            event["file"] = file
        return event

    def start(self) -> None:
        if shutil.which("bpftrace") is None:
            self.status = "bpftrace not installed"
            return
        try:
            self.proc = subprocess.Popen(["sudo", "-n", "bpftrace", "-e", self._SCRIPT], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.status = "tracing"
        except OSError as exc:
            self.status = f"failed to start: {exc}"

    def stop(self, limit: int = 200) -> None:
        if not self.proc:
            return
        subprocess.run(["sudo", "-n", "pkill", "-x", "bpftrace"], capture_output=True)
        try:
            out, err = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, err = self.proc.communicate()
        for line in out.splitlines():
            parsed = self.parse_line(line)
            if parsed:
                self.observations.append(parsed)
            if len(self.observations) >= limit:
                break
        if "password is required" in err:
            self.status = "sudo NOPASSWD for bpftrace not configured (see scripts/setup_ubuntu.sh)"
        elif self.proc.returncode not in (0, None) and not self.observations:
            self.status = f"failed: {err.strip().splitlines()[0] if err.strip() else 'unknown'}"
        else:
            self.status = f"success ({len(self.observations)} host-boundary observations)"
