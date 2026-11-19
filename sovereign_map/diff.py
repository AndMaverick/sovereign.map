"""What a change does to compliance. Run it on a pull request: compare the architecture before and after under one policy."""
from __future__ import annotations

from dataclasses import dataclass

from .engine import evaluate
from .model import Architecture, Finding, Flow
from .policy import Policy


@dataclass(frozen=True)
class Diff:
    new: tuple[Finding, ...]            # findings in ``after`` that were not in ``before``
    resolved: tuple[Finding, ...]       # findings in ``before`` that are gone
    exposure_added: dict[str, list[str]]  # data class -> jurisdictions it now touches that it did not before
    exposure_removed: dict[str, list[str]]
    egress_added: tuple[Flow, ...]
    nodes_added: tuple[str, ...]
    nodes_removed: tuple[str, ...]
    flows_added: tuple[Flow, ...]
    flows_removed: tuple[Flow, ...]

    @property
    def new_errors(self) -> list[Finding]:
        return [f for f in self.new if f.severity == "error"]

    @property
    def worse(self) -> bool:
        """True when the change adds an error."""
        return bool(self.new_errors)

    def to_dict(self) -> dict[str, object]:
        return {
            "worse": self.worse,
            "new": [f.to_dict() for f in self.new], "resolved": [f.to_dict() for f in self.resolved],
            "exposure_added": self.exposure_added, "exposure_removed": self.exposure_removed,
            "egress_added": [f.label for f in self.egress_added],
            "nodes_added": list(self.nodes_added), "nodes_removed": list(self.nodes_removed),
            "flows_added": [f.label for f in self.flows_added], "flows_removed": [f.label for f in self.flows_removed],
        }


def diff(before: Architecture, after: Architecture, policy: Policy, *, lint: bool = False) -> Diff:
    """Findings are matched by rule, node and flow (not by wording), so rewording a message never shows up as a change."""
    b, a = evaluate(before, policy, lint=lint), evaluate(after, policy, lint=lint)
    bk = {f.key(): f for f in b.findings}
    ak = {f.key(): f for f in a.findings}
    new = tuple(f for k, f in ak.items() if k not in bk)
    resolved = tuple(f for k, f in bk.items() if k not in ak)
    added: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    for cls in sorted(set(b.exposure) | set(a.exposure)):
        was, now = set(b.exposure.get(cls, [])), set(a.exposure.get(cls, []))
        if now - was:
            added[cls] = sorted(now - was)
        if was - now:
            removed[cls] = sorted(was - now)
    bflows, aflows = set(before.flows), set(after.flows)
    egress_b, egress_a = {(f.src, f.dst, f.data_class) for f in b.egress}, a.egress
    return Diff(new, resolved, added, removed, tuple(f for f in egress_a if (f.src, f.dst, f.data_class) not in egress_b),
                tuple(sorted(set(after.nodes) - set(before.nodes))), tuple(sorted(set(before.nodes) - set(after.nodes))),
                tuple(sorted(aflows - bflows, key=lambda f: f.label)), tuple(sorted(bflows - aflows, key=lambda f: f.label)))
