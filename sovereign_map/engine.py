"""Evaluating an architecture against a policy."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from . import __version__
from .graph import egress, exposure, orphans
from .labels import Matcher, is_unknown, same_jurisdiction
from .model import Architecture, Finding, Flow, Node, as_architecture, fingerprint
from .policy import Policy

RULES = {
    "unknown-node": "A flow names a node that is not declared.",
    "processing": "Data is processed in a jurisdiction the policy does not allow for its class.",
    "deny": "Data touches a jurisdiction the policy forbids for its class.",
    "control": "A node that handles the data is operated under a jurisdiction the policy does not allow.",
    "control-undeclared": "A control rule applies but the node does not declare who operates it.",
    "transfer": "A cross-border flow does not name an accepted transfer mechanism.",
    "protection": "A cross-border flow lacks a protection the policy requires.",
    "orphan-node": "A declared node has no flows, so the model may be missing one.",
    "unknown-location": "A node has no known jurisdiction.",
    "unruled-class": "A data class has no rule and is not declared open, so it is unrestricted by default.",
    "unused-rule": "A rule names a data class no flow carries, which can be a typo.",
}


@dataclass
class Report:
    """Everything a run found, tied to the exact inputs by ``fingerprint``."""

    findings: tuple[Finding, ...]
    fingerprint: str
    exposure: dict[str, list[str]]
    egress: tuple[Flow, ...]
    nodes_checked: int
    flows_checked: int
    policy_name: str = ""
    home: str = ""

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]

    @property
    def ok(self) -> bool:
        """No errors. Warnings do not fail a run unless you gate on them."""
        return not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "sovereign.map", "version": __version__, "fingerprint": self.fingerprint, "ok": self.ok,
            "policy": self.policy_name, "home": self.home,
            "summary": {"errors": len(self.errors), "warnings": len(self.warnings), "nodes": self.nodes_checked, "flows": self.flows_checked},
            "findings": [f.to_dict() for f in self.findings],
            "exposure": self.exposure,
            "egress": [{"src": f.src, "dst": f.dst, "data_class": f.data_class} for f in self.egress],
        }


def evaluate(arch: Architecture, policy: Policy, *, lint: bool = False) -> Report:
    """Check every flow against the policy. With ``lint=True`` also report modelling problems (orphans, unknown locations,
    classes with no rule, rules for classes nothing carries) as warnings."""
    findings: list[Finding] = []
    matcher = Matcher(policy.all_groups(), hierarchical=policy.hierarchical)
    for flow in arch.flows:
        findings.extend(flow_findings(arch, policy, flow, matcher))
    if lint:
        findings.extend(_lint(arch, policy))
    ordered = tuple(sorted(set(findings), key=lambda f: f.sort_key()))
    leaving = egress(arch, None, policy.home, groups=policy.all_groups(), hierarchical=policy.hierarchical) if policy.home else []
    return Report(ordered, fingerprint(arch, policy.to_dict()), exposure(arch), tuple(leaving), len(arch.nodes), len(arch.flows), policy.name,
                  policy.home)


def check(nodes: Architecture | Mapping[str, Node], flows: Iterable[Flow] | None, allowed: Mapping[str, Iterable[str]] | Policy) -> list[Finding]:
    """Every finding for a flow list. ``allowed`` is either a Policy or the 0.1 mapping of data class to the jurisdictions it may be
    processed in. Both ends of a flow must comply, because data is processed at the source as well as the destination."""
    arch = as_architecture(nodes, flows)
    policy = allowed if isinstance(allowed, Policy) else Policy.from_allowed(allowed)
    return list(evaluate(arch, policy).findings)


def audit(arch: Architecture, policy: Policy) -> Report:
    """``evaluate`` with the modelling lint switched on."""
    return evaluate(arch, policy, lint=True)


def flow_findings(arch: Architecture, policy: Policy, flow: Flow, matcher: Matcher | None = None) -> list[Finding]:
    src, dst = arch.nodes.get(flow.src), arch.nodes.get(flow.dst)
    missing = [n for n in dict.fromkeys((flow.src, flow.dst)) if n not in arch.nodes]
    if missing:
        return [Finding(flow, f"unknown node: {', '.join(missing)}", "unknown-node", hint="declare the node, or fix the name in the flow")]
    assert src is not None and dst is not None
    out: list[Finding] = []
    ends = list(dict.fromkeys((src, dst)))
    m = matcher or Matcher(policy.all_groups(), hierarchical=policy.hierarchical)
    hier = policy.hierarchical
    for cls in policy.lineage(flow.data_class):
        via = "" if cls == flow.data_class else f" (inherited from {cls})"
        permitted = policy.processing.get(cls)
        for node in ends:
            where = node.jurisdiction
            if permitted is not None and not m.any(permitted, where):
                place = "an unknown location" if is_unknown(where) else where
                out.append(Finding(flow, f"{flow.data_class} may not be processed in {place} ({node.name}){via}", "processing",
                                   node=node.name, hint=_processing_hint(arch, m, node, permitted)))
            banned = policy.deny.get(cls)
            if banned is not None and m.any(banned, where):
                out.append(Finding(flow, f"{flow.data_class} is forbidden in {where} ({node.name}){via}", "deny", node=node.name,
                                   hint=f"never allowed in: {', '.join(sorted(banned))}"))
            allowed_control = policy.control.get(cls)
            if allowed_control is not None:
                if not node.operator.strip():
                    out.append(Finding(flow, f"{node.name} does not declare who operates it, so control of {flow.data_class} cannot be checked{via}",
                                       "control-undeclared", "warning", node.name, "set the node's operator"))
                elif not m.any(allowed_control, node.operator):
                    out.append(Finding(flow, f"{flow.data_class} is handled by {node.name}, operated under {node.operator} law{via}", "control",
                                       node=node.name, hint=f"operator must be under: {', '.join(sorted(allowed_control))}"))
        rule = policy.transfer.get(cls)
        if rule is not None and not same_jurisdiction(src.jurisdiction, dst.jurisdiction, hierarchical=hier):
            free = any(m.covers(g, src.jurisdiction) and m.covers(g, dst.jurisdiction) for g in rule.free_within)
            if not free:
                if rule.mechanisms and flow.mechanism.casefold() not in rule.mechanisms:
                    named = flow.mechanism or "none"
                    out.append(Finding(flow, f"{flow.data_class} crosses {src.jurisdiction} to {dst.jurisdiction} with mechanism {named!r}{via}",
                                       "transfer", hint=f"accepted: {', '.join(sorted(rule.mechanisms))}"))
                lacking = sorted(rule.protections - {p.casefold() for p in flow.protections})
                if lacking:
                    out.append(Finding(flow, f"{flow.data_class} crosses {src.jurisdiction} to {dst.jurisdiction} without {', '.join(lacking)}{via}",
                                       "protection", hint=f"required on this flow: {', '.join(sorted(rule.protections))}"))
    return out


def _processing_hint(arch: Architecture, m: Matcher, node: Node, permitted: frozenset[str]) -> str:
    text = f"permitted: {', '.join(sorted(permitted))}"
    if node.kind:
        key = ("alts", node.kind, permitted)
        compliant = m.scratch.get(key)
        if compliant is None:
            compliant = m.scratch[key] = sorted(n.name for n in arch.nodes.values() if n.kind == node.kind and m.any(permitted, n.jurisdiction))
        alts = [n for n in compliant if n != node.name]
        if alts:
            text += f"; compliant {node.kind} already in this architecture: {', '.join(alts)}"
    return text


def _lint(arch: Architecture, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    for name in orphans(arch):
        out.append(Finding(None, f"{name} has no flows", "orphan-node", "warning", name, "add the flows it takes part in, or remove it"))
    for node in arch.nodes.values():
        if is_unknown(node.jurisdiction):
            out.append(Finding(None, f"{node.name} has no known jurisdiction", "unknown-location", "warning", node.name,
                               "restricted data sent here is always a finding"))
    used = {f.data_class for f in arch.flows}
    ruled, opened = policy.ruled_classes(), policy.open
    for cls in sorted(used):
        lineage = policy.lineage(cls)
        if not any(c in ruled or c in opened for c in lineage):
            out.append(Finding(next(f for f in arch.flows if f.data_class == cls), f"{cls} has no rule and is not declared open", "unruled-class",
                               "warning", hint='add a rule, or list it under "open" to say it is unrestricted on purpose'))
    for cls in sorted(ruled - used):
        out.append(Finding(None, f"a rule names {cls}, which no flow carries", "unused-rule", "warning", hint="check the class name for a typo"))
    return out

