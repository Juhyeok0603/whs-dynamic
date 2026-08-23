import json
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
import httpx
from .config import settings

_TIMEOUT = 10
_TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
_CREATION_DATE_RE = re.compile(r"(?im)^\s*(?:creation date|created(?: on)?|registered on|registration date)\s*:\s*(.+)$")
_YEAR_RE = re.compile(r"\b(19|20)\d{2}\b")


def fetch_registry_meta(package: str, version: str | None) -> dict:
    """PyPI JSON API: publish history + maintainer identity for the analyzed package (same endpoint as
    main.py's search_pypi). requires_dist is intentionally left to package.read_package_metadata() (reads
    the artifact's own METADATA, so it still works if this registry call fails or a mirror was used)."""
    try:
        r = httpx.get(f"https://pypi.org/pypi/{package}/json", timeout=_TIMEOUT)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return {"status": "unavailable", "reason": str(exc)}
    data = r.json()
    info = data.get("info", {})
    releases = data.get("releases", {})
    history = sorted(
        ({"version": v, "upload_time": rels[0].get("upload_time_iso_8601")} for v, rels in releases.items() if rels),
        key=lambda e: e["upload_time"] or "",
    )
    target_version = version or info.get("version")
    target = next((e for e in history if e["version"] == target_version), None)
    days_since_publish = None
    if target and target["upload_time"]:
        try:
            published = datetime.fromisoformat(target["upload_time"].replace("Z", "+00:00"))
            days_since_publish = (datetime.now(timezone.utc) - published).days
        except ValueError:
            pass
    return {
        "status": "success",
        "name": info.get("name"),
        "author": info.get("author"),
        "author_email": info.get("author_email"),
        "maintainer": info.get("maintainer"),
        "maintainer_email": info.get("maintainer_email"),
        "project_urls": info.get("project_urls"),
        "first_published": history[0]["upload_time"] if history else None,
        "target_version": target_version,
        "target_published": target["upload_time"] if target else None,
        "days_since_publish": days_since_publish,
        "release_count": len(history),
        "release_history": history[-20:],
    }


def fetch_download_stats(package: str) -> dict:
    """pypistats.org recent download counts. Public, no API key required."""
    try:
        r = httpx.get(f"https://pypistats.org/api/packages/{package}/recent", timeout=_TIMEOUT)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return {"status": "unavailable", "reason": str(exc)}
    return {"status": "success", **r.json().get("data", {})}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _normalize(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def _load_top_packages(cache_dir: Path, ttl_hours: int) -> tuple[list[str], str | None]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / "top-pypi-packages.json"
    fresh = cache_path.exists() and (time.time() - cache_path.stat().st_mtime) < ttl_hours * 3600
    if not fresh:
        try:
            r = httpx.get(_TOP_PACKAGES_URL, timeout=_TIMEOUT)
            r.raise_for_status()
            cache_path.write_text(r.text, encoding="utf-8")
        except httpx.HTTPError:
            pass  # fall through to stale/absent cache below
    if not cache_path.exists():
        return [], "top-pypi-packages fetch failed and no cache is available"
    try:
        rows = json.loads(cache_path.read_text(encoding="utf-8")).get("rows", [])
    except (ValueError, OSError):
        return [], "cached top-pypi-packages.json is unreadable"
    return [row["project"] for row in rows if "project" in row], None


def typosquat_check(package: str, cache_dir: Path, ttl_hours: int = 168) -> dict:
    popular, reason = _load_top_packages(cache_dir, ttl_hours)
    if reason:
        return {"status": "unavailable", "reason": reason}
    norm = _normalize(package)
    best = None
    for candidate in popular:
        if _normalize(candidate) == norm:
            return {"status": "success", "exact_match_in_top_packages": True, "candidate": None, "distance": 0}
        distance = _levenshtein(norm, _normalize(candidate))
        if distance <= 2 and (best is None or distance < best[1]):
            best = (candidate, distance)
    if best is None:
        return {"status": "success", "exact_match_in_top_packages": False, "candidate": None, "distance": None}
    return {"status": "success", "exact_match_in_top_packages": False, "candidate": best[0], "distance": best[1]}


def _whois_query(server: str, query: str, timeout: int) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("ascii", errors="ignore"))
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")


def whois_lookup(domain: str, timeout: int = 5) -> dict:
    """Minimal WHOIS client: ask IANA for the TLD's authoritative server, then query it directly. No
    library needed (WHOIS is a trivial plaintext TCP/43 protocol) — but response formats vary wildly across
    registries, so date parsing below is best-effort (first matching line wins, falls back to a bare year)."""
    try:
        referral = _whois_query("whois.iana.org", domain, timeout)
    except OSError as exc:
        return {"status": "unavailable", "reason": f"IANA referral failed: {exc}"}
    match = re.search(r"(?im)^whois:\s*(\S+)", referral)
    if not match:
        return {"status": "unavailable", "reason": "no WHOIS server referral found for this TLD"}
    try:
        record = _whois_query(match.group(1), domain, timeout)
    except OSError as exc:
        return {"status": "unavailable", "reason": f"query to {match.group(1)} failed: {exc}"}
    creation_date = None
    date_match = _CREATION_DATE_RE.search(record)
    age_days = None
    if date_match:
        creation_date = date_match.group(1).strip()
        try:
            age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(creation_date.replace("Z", "+00:00"))).days
        except ValueError:
            year_match = _YEAR_RE.search(creation_date)
            if year_match:
                age_days = (datetime.now(timezone.utc) - datetime(int(year_match.group(0)), 1, 1, tzinfo=timezone.utc)).days
    return {"status": "success", "whois_server": match.group(1), "creation_date": creation_date, "age_days": age_days, "raw": record[:2000]}


def domain_reputation(domain: str) -> dict:
    if not settings.vt_api_key:
        return {"status": "not_implemented", "reason": "VT_API_KEY not configured"}
    try:
        r = httpx.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": settings.vt_api_key}, timeout=_TIMEOUT)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        return {"status": "unavailable", "reason": str(exc)}
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"status": "success", "last_analysis_stats": stats}
