import ast
import hashlib
import math
import subprocess
import sys
import tarfile
import zipfile
from collections import Counter
from pathlib import Path
from packaging.version import InvalidVersion, Version

_SUSPICIOUS_APIS = ("eval", "exec", "compile", "os.system", "subprocess", "socket", "base64", "marshal", "ctypes", "pickle", "__import__")
_HIGH_ENTROPY_BITS = 4.5
_HIGH_ENTROPY_MIN_LEN = 40
_LONG_LINE_CHARS = 500


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def extract_source_tree(artifact_path: Path, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    if artifact_path.suffix in (".whl", ".zip"):
        with zipfile.ZipFile(artifact_path) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(artifact_path) as tf:
            tf.extractall(dest, filter="data")
    return dest


def _string_literals(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value


def scan_source_tree(root: Path) -> dict:
    files_scanned = 0
    high_entropy_strings = []
    suspicious_hits: Counter = Counter()
    obfuscation_flags = []
    for path in root.rglob("*.py"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files_scanned += 1
        rel = str(path.relative_to(root))
        for line in text.splitlines():
            if len(line) > _LONG_LINE_CHARS:
                obfuscation_flags.append({"file": rel, "reason": "line longer than %d chars" % _LONG_LINE_CHARS, "length": len(line)})
        for api in _SUSPICIOUS_APIS:
            hits = text.count(api)
            if hits:
                suspicious_hits[api] += hits
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            continue
        for literal in _string_literals(tree):
            if len(literal) >= _HIGH_ENTROPY_MIN_LEN:
                entropy = shannon_entropy(literal)
                if entropy >= _HIGH_ENTROPY_BITS:
                    high_entropy_strings.append({"file": rel, "length": len(literal), "entropy_bits_per_char": round(entropy, 2), "preview": literal[:60]})
    return {
        "files_scanned": files_scanned,
        "high_entropy_strings": high_entropy_strings[:50],
        "suspicious_api_hits": dict(suspicious_hits),
        "obfuscation_flags": obfuscation_flags[:50],
    }


def _previous_version(current_version: str | None, release_history: list[dict]) -> str | None:
    if not current_version:
        return None
    try:
        current = Version(current_version)
    except InvalidVersion:
        return None
    older = []
    for entry in release_history:
        try:
            v = Version(entry["version"])
        except InvalidVersion:
            continue
        if v < current:
            older.append(v)
    return str(max(older)) if older else None


def diff_against_previous_release(package: str, current_version: str | None, release_history: list[dict], current_root: Path, workspace: Path) -> dict:
    """Best-effort: downloads the immediately-prior published release (host-side pip download, independent
    of the sandbox's network mode) and hash-diffs its source tree against the analyzed one."""
    previous_version = _previous_version(current_version, release_history)
    if previous_version is None:
        return {"status": "unavailable", "reason": "no earlier published release found"}
    dest = workspace / "_prev_release"
    dest.mkdir(exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--no-deps", "--retries", "1", "--timeout", "15", "--dest", str(dest), f"{package}=={previous_version}"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return {"status": "unavailable", "reason": result.stderr.strip()[:500] or "pip download failed"}
    artifact = next((p for p in dest.iterdir() if p.suffix in (".whl", ".gz", ".zip")), None)
    if artifact is None:
        return {"status": "unavailable", "reason": "no artifact downloaded for previous release"}
    prev_root = extract_source_tree(artifact, dest / "src")
    prev_files = {str(p.relative_to(prev_root)): p for p in prev_root.rglob("*.py")}
    cur_files = {str(p.relative_to(current_root)): p for p in current_root.rglob("*.py")}
    hash_of = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    added = sorted(cur_files.keys() - prev_files.keys())
    removed = sorted(prev_files.keys() - cur_files.keys())
    changed = sorted(name for name in cur_files.keys() & prev_files.keys() if hash_of(cur_files[name]) != hash_of(prev_files[name]))
    return {"status": "success", "previous_version": previous_version, "files_added": added, "files_removed": removed, "files_changed": changed}
