from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnalysisRequest(BaseModel):
    package: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:==[A-Za-z0-9.*+!._-]+)?$")
    version: str | None = None
    artifact: Literal["auto", "wheel", "sdist"] = "auto"
    network: Literal["disabled", "restricted", "full", "sinkhole"] = "restricted"
    timeout: int = Field(default=240, ge=5, le=3600)
    custom_command: list[str] | None = None


class NormalizedEvent(BaseModel):
    timestamp: str = Field(default_factory=now)
    source: str
    category: str
    type: str
    stage: str
    pid: int | None = None
    ppid: int | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class StageResult(BaseModel):
    name: str
    status: str
    started_at: str
    finished_at: str
    duration_seconds: float
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timeout: bool = False
    events: list[NormalizedEvent] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float = Field(ge=0, le=1)
    stage: str
    evidence: list[NormalizedEvent] = Field(default_factory=list)
    repeat_count: int = 1


class AnalysisReport(BaseModel):
    schema_version: str = "1.0"
    analysis_id: str
    package: dict[str, Any]
    analysis: dict[str, Any]
    sandbox: dict[str, Any]
    summary: dict[str, Any]
    stages: list[StageResult]
    findings: list[Finding]
    behavior: dict[str, Any]
    filesystem_diff: dict[str, list[Any]]
    resource_usage: dict[str, Any]
    behavior_chains: list[dict[str, Any]]
    collector_status: dict[str, str]
    errors: list[str]
    signals: dict[str, Any] = Field(default_factory=dict)
