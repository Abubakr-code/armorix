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

    @property
    def key(self) -> tuple:
        return (self.rule_id, self.file, self.line)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name.lower()
        return data
