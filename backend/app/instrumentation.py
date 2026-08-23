import json
from pathlib import Path

ENV_LOG_NAME = "_env-access.log"
CODE_LOG_NAME = "_code-exec.log"

# Auto-imported by CPython's site module at interpreter startup (via PYTHONPATH=/workspace) for every
# sandboxed invocation (-m pip, -c, console-script probes) without needing to rewrite each stage's command.
# sys.addaudithook covers compile/exec/import (real CPython audit events); plain os.environ reads are NOT
# audited by CPython, so env access is caught by wrapping os.environ in a logging proxy instead (mirrors the
# Node.js process.env Proxy approach). Every hook body is wrapped in try/except: raising from an audit hook
# propagates into the audited program and would break pip install itself.
_SITECUSTOMIZE_SOURCE = '''\
import json, os, sys, time

_STAGE = os.environ.get("DAST_STAGE", "unknown")
_WORKSPACE = os.environ.get("DAST_WORKSPACE", "/workspace")
_ENV_LOG = os.path.join(_WORKSPACE, "%(env_log)s")
_CODE_LOG = os.path.join(_WORKSPACE, "%(code_log)s")
_MAX_LINES = 2000
_counts = {"env": 0, "code": 0}


def _write(path, kind, row):
    if _counts[kind] >= _MAX_LINES:
        return
    _counts[kind] += 1
    row["timestamp"] = time.time()
    row["stage"] = _STAGE
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\\n")
    except OSError:
        pass


def _s(value, limit=200):
    try:
        return str(value)[:limit]
    except Exception:
        return None


class _EnvProxy(os._Environ):
    def __init__(self, real):
        self.__dict__.update(real.__dict__)

    def __iter__(self):
        try:
            _write(_ENV_LOG, "env", {"event": "bulk_iteration", "via": "__iter__"})
        except Exception:
            pass
        return super().__iter__()

    def keys(self):
        try:
            _write(_ENV_LOG, "env", {"event": "bulk_iteration", "via": "keys"})
        except Exception:
            pass
        return super().keys()

    def items(self):
        try:
            _write(_ENV_LOG, "env", {"event": "bulk_iteration", "via": "items"})
        except Exception:
            pass
        return super().items()

    def __getitem__(self, key):
        try:
            _write(_ENV_LOG, "env", {"event": "access", "key": _s(key, 100)})
        except Exception:
            pass
        return super().__getitem__(key)

    def get(self, key, default=None):
        try:
            _write(_ENV_LOG, "env", {"event": "access", "key": _s(key, 100)})
        except Exception:
            pass
        return super().get(key, default)


def _audit_hook(event, args):
    try:
        if event == "compile":
            source, filename = (args[0] if args else None), (args[1] if len(args) > 1 else None)
            src = _s(source)
            _write(_CODE_LOG, "code", {"event": "compile", "filename": _s(filename), "source_head": src, "source_len": len(src) if src else 0})
        elif event == "exec":
            code = args[0] if args else None
            _write(_CODE_LOG, "code", {"event": "exec", "filename": _s(getattr(code, "co_filename", None))})
        elif event == "import":
            module = args[0] if args else None
            filename = args[1] if len(args) > 1 else None
            _write(_CODE_LOG, "code", {"event": "import", "module": _s(module, 200), "filename": _s(filename)})
    except Exception:
        pass


try:
    os.environ = _EnvProxy(os.environ)
except Exception:
    pass
try:
    sys.addaudithook(_audit_hook)
except Exception:
    pass
'''


def bootstrap_source() -> str:
    return _SITECUSTOMIZE_SOURCE % {"env_log": ENV_LOG_NAME, "code_log": CODE_LOG_NAME}


def write_bootstrap(workspace: Path) -> None:
    """Writes sitecustomize.py into the workspace so PYTHONPATH=/workspace auto-loads it for every
    sandboxed python invocation (pip install, -c, console-script probes) without touching stage commands."""
    (workspace / "sitecustomize.py").write_text(bootstrap_source(), encoding="utf-8")


def stage_env(workspace_container_path: str = "/workspace", stage: str = "", ca_path: str | None = None) -> dict[str, str]:
    env = {"PYTHONPATH": workspace_container_path, "DAST_WORKSPACE": workspace_container_path, "DAST_STAGE": stage}
    if ca_path:
        # Trusts the sinkhole's per-analysis MITM CA so its dynamically-issued leaf certs verify. Covers
        # the stdlib ssl module (SSL_CERT_FILE) and requests/urllib3 (REQUESTS_CA_BUNDLE overrides
        # certifi's bundled CAs) and curl-based tools (CURL_CA_BUNDLE) — code that pins its own CA bundle
        # or disables verification outright still won't be interceptable, same limitation any MITM has.
        env.update(SSL_CERT_FILE=ca_path, REQUESTS_CA_BUNDLE=ca_path, CURL_CA_BUNDLE=ca_path)
    return env


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows
