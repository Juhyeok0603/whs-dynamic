import json
from pathlib import Path
from typing import Any


def save_report(root: Path, report: Any) -> Path:
    target = root / report.analysis_id
    (target / "raw").mkdir(parents=True, exist_ok=True)
    (target / "logs").mkdir(exist_ok=True)
    path = target / "report.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_report(root: Path, analysis_id: str) -> dict[str, Any] | None:
    path = root / analysis_id / "report.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
