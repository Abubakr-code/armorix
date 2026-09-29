from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        return cls[name.upper()]


@dataclass
class TraceStep:
    """One hop of a source → sink path, shown under the finding."""

    line: int
    code: str
    label: str  # "source", "flows", "sink"


@dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: Severity
    title: str
    message: str
    fix: str
    file: str
    line: int
    column: int
    snippet: str
    trace: list[TraceStep] = field(default_factory=list)
    data: dict = field(default_factory=dict)  # structured details for localisation (source, package, …)
    fingerprint: str = ""  # line-independent id (baseline, history diff); set by the scanner

    @property
    def key(self) -> tuple:
        return (self.rule_id, self.file, self.line)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = dict(data)
        data["severity"] = Severity.parse(data["severity"]) if isinstance(data["severity"], str) else Severity(data["severity"])
        data["trace"] = [TraceStep(**{k: s[k] for k in ("line", "code", "label")}) for s in data.get("trace", [])]
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in known})
