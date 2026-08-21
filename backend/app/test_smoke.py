from pathlib import Path
from .collectors import FilesystemCollector
from .analyzer import analyze
from .schemas import NormalizedEvent


def test_filesystem_diff(tmp_path: Path):
    before = FilesystemCollector().snapshot([tmp_path]); (tmp_path / "x").write_text("x"); after = FilesystemCollector().snapshot([tmp_path])
    assert after["%s" % (tmp_path / "x")]["size"] == 1
    assert len(FilesystemCollector().diff(before, after)["created"]) == 1


def test_sensitive_read_finding():
    event = NormalizedEvent(source="gvisor", category="file", type="file.read", stage="import", data={"path": "/home/analyzer/.aws/credentials"})
    findings, score, _ = analyze([event])
    assert findings[0].rule_id == "file.sensitive_read"
    assert score >= 45
