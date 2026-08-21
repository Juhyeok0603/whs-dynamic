import json
import os
import shutil
import subprocess
from pathlib import Path
from .config import settings


class SandboxUnavailable(RuntimeError): pass


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


def docker_command(workspace: Path, command: list[str], network: str, runtime: str = settings.sandbox_runtime) -> list[str]:
    # Restricted remains offline until an explicit allowlist proxy is configured.
    network_arg = "none" if network in {"disabled", "restricted"} else "bridge"
    user_args = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    return ["docker", "run", "--rm", "--runtime", runtime, "--network", network_arg, *user_args, "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", "--cpus", "1", "--memory", "512m", "--pids-limit", "128", "-v", f"{workspace}:/workspace:rw", "python:3.12-slim", *command]
