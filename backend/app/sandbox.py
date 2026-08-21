import json
import os
import shutil
import subprocess
from pathlib import Path
from .config import settings


class SandboxUnavailable(RuntimeError): pass


def check_runtime() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker is unavailable"
    result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=10)
    if result.returncode:
        return False, result.stderr.strip() or "Docker daemon is unavailable"
    runtime = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True, timeout=10)
    if settings.sandbox_runtime not in runtime.stdout:
        return False, f"Docker runtime {settings.sandbox_runtime!r} is not configured"
    return True, "ready"


def docker_command(workspace: Path, command: list[str], network: str) -> list[str]:
    # Restricted remains offline until an explicit allowlist proxy is configured.
    network_arg = "none" if network in {"disabled", "restricted"} else "bridge"
    user_args = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
    return ["docker", "run", "--rm", "--runtime", settings.sandbox_runtime, "--network", network_arg, *user_args, "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", "--cpus", "1", "--memory", "512m", "--pids-limit", "128", "-v", f"{workspace}:/workspace:rw", "python:3.12-slim", *command]
