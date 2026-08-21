from pathlib import Path
import hashlib
import os
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
