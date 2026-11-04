"""Finding model and severity ordering shared by every scanner backend.

A Finding is a single observation about one file. Severities are ordered so the
CLI can gate on a threshold (`--fail-on`) and so reports can sort worst-first.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0       # informational, never fails a gate (e.g. "this is safetensors, good")
    LOW = 1        # weak signal, likely benign
    MEDIUM = 2     # worth a human look; the opcode-invisible string-data heuristics live here
    HIGH = 3       # a dangerous import reachable on load
    CRITICAL = 4   # confirmed code-execution shape, or a scanner-evasion construct

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {name!r}; "
                             f"choose from {', '.join(s.name.lower() for s in cls)}")


@dataclass
class Finding:
    severity: Severity
    code: str            # stable machine id, e.g. "pickle.reduce_exec"
    message: str         # one human-readable line
    path: str            # file scanned
    member: str | None = None   # archive member, if inside a zip-based model
    detail: dict[str, Any] = field(default_factory=dict)

    def location(self) -> str:
        return f"{self.path}::{self.member}" if self.member else self.path

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d
