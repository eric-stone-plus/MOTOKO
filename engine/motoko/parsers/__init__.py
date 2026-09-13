"""Observation contract + parser registry.

The Observation contract is the normalization layer between raw tool output
and the graph (grok review P0: without it the SYNC phase is empty). Every
parser converts a tool's stdout/stderr into structured assets + findings;
anything it cannot parse goes to ``dead_letter`` — never silently dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .. import confidence, dedup, util


@dataclass
class ParsedObservation:
    """Normalized result of one tool invocation."""

    tool: str
    summary: str
    assets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    dead_letter: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.assets or self.findings or self.services)


class Parser:
    """Base parser. Subclasses set ``tool`` and implement ``parse``."""

    tool: str = ""

    def parse(self, stdout: str, stderr: str = "", action: dict | None = None) -> ParsedObservation:
        raise NotImplementedError

    # -- helpers -------------------------------------------------------
    def _finding(self, *, class_: str, title: str, url: str, param: str | None = None,
                 sink: str | None = None, severity: str = "unknown",
                 source: str | None = None, extra: dict | None = None) -> dict:
        """Build a standard candidate finding with prior confidence + dedup key."""
        f: dict = {
            "id": util.new_id("finding"),
            "kind": "finding",
            "state": "candidate",
            "class": class_,
            "title": title,
            "url": url,
            "param": param,
            "sink": sink,
            "severity": severity,
            "detector": source or self.tool,
            "signals": [],
        }
        if extra:
            f.update(extra)
        f["confidence"] = confidence.prior_for(source or self.tool)
        f["dedup_key"] = dedup.compute_dedup_key(f)
        return f

    def _asset(self, *, type_: str, value: str, extra: dict | None = None) -> dict:
        a: dict = {
            "id": util.new_id("asset"),
            "kind": "asset",
            "state": "active",
            "type": type_,
            "value": value,
            "source": self.tool,
        }
        if extra:
            a.update(extra)
        return a

    def _result(self, summary: str, *, assets: list[dict] | None = None,
                findings: list[dict] | None = None,
                dead_letter: list[str] | None = None,
                services: list[dict] | None = None) -> ParsedObservation:
        return ParsedObservation(
            tool=self.tool,
            summary=summary,
            assets=assets or [],
            findings=findings or [],
            dead_letter=dead_letter or [],
            services=services or [],
        )


# Registry (populated at import time by each parser module).
_REGISTRY: dict[str, Parser] = {}


def register(cls: type[Parser]) -> type[Parser]:
    """Class decorator: instantiate the parser and register it by ``tool``."""
    inst = cls()
    _REGISTRY[inst.tool] = inst
    return cls


def get_parser(tool: str) -> Parser | None:
    return _REGISTRY.get(tool)


def parse_tool(tool: str, stdout: str, stderr: str = "",
               action: dict | None = None) -> ParsedObservation:
    """Parse a tool's output, or return a dead-letter result if unregistered."""
    p = get_parser(tool)
    if p is None:
        return ParsedObservation(
            tool=tool,
            summary=f"no parser registered for tool '{tool}'",
            dead_letter=[stdout[:2000]] if stdout else [],
        )
    return p.parse(stdout, stderr, action)


# Import parser modules so they self-register.
from . import arjun, curl, dalfox, ffuf, httpx, jsluice, katana, lines, nmap, nuclei, sqlmap, strix  # noqa: E402,F401

__all__ = [
    "ParsedObservation", "Parser", "register", "get_parser", "parse_tool",
]
