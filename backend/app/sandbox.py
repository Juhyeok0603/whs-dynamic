import json
import os
import shutil
import subprocess
from pathlib import Path
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version
from .config import settings

_DEFAULT_PYTHON_VERSION = "3.12"
_DEFAULT_PYTHON_IMAGE = f"python:{_DEFAULT_PYTHON_VERSION}-slim"
# Official python:X.Y-slim tags we've actually run gVisor + our sitecustomize instrumentation against.
# Anything a package's Requires-Python needs outside this range falls back to the default rather than
# guessing at an untested image tag.
_SUPPORTED_PYTHON_VERSIONS = ("3.8", "3.9", "3.10", "3.11", "3.12", "3.13")


class SandboxUnavailable(RuntimeError): pass


def select_python_image(requires_python: str | None) -> str:
    """Picks a python:X.Y-slim image whose version satisfies the package's own declared Requires-Python
    (PEP 440 specifier) — some real-world packages (seen on actual malicious samples generated from a
    stale cookiecutter template) only support e.g. '<3.9,>=3.8.0' and simply can't build/install under
    whatever single Python version the sandbox happens to run. Prefers the existing default (3.12) whenever
    it already satisfies the constraint — which covers the overwhelming majority of ordinary packages, who
    just declare a lower bound like '>=3.8' with no upper bound — so this only ever deviates for a package
    that genuinely can't run under 3.12; ordinary analyses keep using the already-pulled-and-tested image
    instead of racing a first-time pull of some other version against a sandboxed stage's own timeout."""
    if not requires_python:
        return _DEFAULT_PYTHON_IMAGE
    try:
        spec = SpecifierSet(requires_python)
    except InvalidSpecifier:
        return _DEFAULT_PYTHON_IMAGE
    if spec.contains(_DEFAULT_PYTHON_VERSION, prereleases=True):
        return _DEFAULT_PYTHON_IMAGE
    candidates = [v for v in _SUPPORTED_PYTHON_VERSIONS if spec.contains(v, prereleases=True)]
    if not candidates:
        return _DEFAULT_PYTHON_IMAGE
    chosen = max(candidates, key=Version)
    return f"python:{chosen}-slim"


def ensure_python_image_pulled(image: str, timeout: int = 300) -> None:
    """Pre-pulls a non-default python image (see select_python_image) so a first-time multi-layer pull
    doesn't have to compete with a sandboxed stage's own, much shorter timeout (e.g. 'install' only gets
    60s total — a fresh image pull alone can already eat 10-20s+, causing a real 'install' to time out
    before pip even starts, as seen in practice). Best-effort and skipped entirely for the default image
    (already expected to be present from ordinary use) — if docker itself is unavailable or the pull fails,
    the first sandboxed stage's own docker run surfaces the real underlying error instead."""
    if image == _DEFAULT_PYTHON_IMAGE:
        return
    try:
        inspect = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=10)
        if inspect.returncode == 0:
            return
        subprocess.run(["docker", "pull", image], capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        pass


def check_runtime() -> tuple[bool, str, str]:
    """Returns (ready, reason, runtime). Prefers the strace-enabled '<runtime>-trace' variant when configured."""
    if shutil.which("docker") is None:
        return False, "docker is unavailable", settings.sandbox_runtime
    result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=10)
    if result.returncode:
        return False, result.stderr.strip() or "Docker daemon is unavailable", settings.sandbox_runtime
    runtime = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True, timeout=10)
    if settings.sandbox_runtime not in runtime.stdout:
        return False, f"Docker runtime {settings.sandbox_runtime!r} is not configured", settings.sandbox_runtime
    trace = f"{settings.sandbox_runtime}-trace"
    return True, "ready", (trace if trace in runtime.stdout else settings.sandbox_runtime)


def docker_command(workspace: Path, command: list[str], network: str, runtime: str = settings.sandbox_runtime, env: dict[str, str] | None = None, dns: str | None = None, docker_network: str | None = None, python_image: str = _DEFAULT_PYTHON_IMAGE) -> list[str]:
    # Restricted remains offline until an explicit allowlist proxy is configured. sinkhole needs its own
    # per-analysis docker network (docker_network) instead of the default bridge, so its NAT rule can
    # target that network's subnet specifically without catching other containers on the host.
    network_arg = docker_network if docker_network else ("none" if network in {"disabled", "restricted"} else "bridge")
    user_args = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    env_args = [arg for key, value in (env or {}).items() for arg in ("-e", f"{key}={value}")]
    dns_args = ["--dns", dns] if dns else []
    return ["docker", "run", "--rm", "--runtime", runtime, "--network", network_arg, *dns_args, *user_args, "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", "--cpus", "1", "--memory", "512m", "--pids-limit", "128", *env_args, "-v", f"{workspace}:/workspace:rw", python_image, *command]
