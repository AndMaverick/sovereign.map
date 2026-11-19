"""sovereign.map: model where data goes when an AI system runs and check it against residency, control and transfer rules you
define. Not legal advice: it enforces the rules you give it and does not know what the law requires."""
from __future__ import annotations

__version__ = "0.2.0"

from .diff import Diff, diff  # noqa: E402
from .engine import RULES, Report, audit, check, evaluate, flow_findings  # noqa: E402
from .graph import cross_border, egress, exposure, holders, orphans, paths, reach, sinks  # noqa: E402
from .labels import BUILTIN_GROUPS, covers  # noqa: E402
from .model import Architecture, Finding, Flow, Node, Violation, fingerprint  # noqa: E402
from .policy import Policy, TransferRule  # noqa: E402
from .render import to_dot, to_markdown, to_mermaid, to_sarif, to_text  # noqa: E402

__all__ = [
    "BUILTIN_GROUPS", "RULES", "Architecture", "Diff", "Finding", "Flow", "Node", "Policy", "Report", "TransferRule", "Violation",
    "audit", "check", "covers", "cross_border", "diff", "egress", "evaluate", "exposure", "fingerprint", "flow_findings", "holders",
    "orphans", "paths", "reach", "sinks", "to_dot", "to_markdown", "to_mermaid", "to_sarif", "to_text",
]
