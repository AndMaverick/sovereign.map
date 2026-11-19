"""Reports and diagrams: plain text, Markdown, Graphviz DOT, Mermaid and SARIF 2.1.0."""
from __future__ import annotations

from typing import Any

from . import __version__
from .engine import RULES, Report
from .graph import cross_border
from .model import Architecture, Flow


def to_text(report: Report) -> str:
    lines = [f"sovereign.map {__version__}  fingerprint {report.fingerprint[:16]}",
             f"{report.nodes_checked} nodes, {report.flows_checked} flows: {len(report.errors)} errors, {len(report.warnings)} warnings"]
    for f in report.findings:
        where = f" [{f.flow.label}]" if f.flow else ""
        lines.append(f"  {f.severity.upper():7} {f.rule}{where}: {f.reason}")
        if f.hint:
            lines.append(f"          fix: {f.hint}")
    for cls, places in report.exposure.items():
        lines.append(f"  exposure {cls}: {', '.join(places)}")
    if report.home:
        lines.append(f"  egress from {report.home}: {len(report.egress)} flow(s)")
        lines.extend(f"    {f.label}" for f in report.egress)
    lines.append("PASS" if report.ok else "FAIL")
    return "\n".join(lines)


def to_markdown(report: Report, arch: Architecture | None = None) -> str:
    out = ["# Data residency report", "",
           f"`{report.fingerprint}`  ",
           f"{report.nodes_checked} nodes, {report.flows_checked} flows. **{'PASS' if report.ok else 'FAIL'}**: "
           f"{len(report.errors)} errors, {len(report.warnings)} warnings.", ""]
    if report.findings:
        out += ["## Findings", "", "| Severity | Rule | Flow | Finding | Fix |", "|---|---|---|---|---|"]
        for f in report.findings:
            out.append(f"| {f.severity} | {f.rule} | {f.flow.label if f.flow else ''} | {_cell(f.reason)} | {_cell(f.hint)} |")
        out.append("")
    out += ["## Exposure", "", "| Data class | Jurisdictions touched |", "|---|---|"]
    out += [f"| {cls} | {', '.join(places)} |" for cls, places in report.exposure.items()]
    if arch is not None:
        crossings = cross_border(arch)
        if crossings:
            out += ["", "## Cross-border", "", "| From | To | Data classes |", "|---|---|---|"]
            out += [f"| {a} | {b} | {', '.join(c)} |" for (a, b), c in crossings.items()]
    if report.home:
        out += ["", f"## Egress from {report.home}", ""]
        out += [f"- {f.label}" for f in report.egress] or ["None."]
    out += ["", "This report applies the rules supplied to it. It is not legal advice."]
    return "\n".join(out) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _bad_flows(report: Report | None) -> set[Flow]:
    return {f.flow for f in report.findings if f.flow and f.severity == "error"} if report else set()


def to_dot(arch: Architecture, report: Report | None = None) -> str:
    """Graphviz DOT with one cluster per jurisdiction. Flows with an error are red and dashed."""
    bad = _bad_flows(report)
    by_place: dict[str, list[str]] = {}
    for n in sorted(arch.nodes.values(), key=lambda x: x.name):
        by_place.setdefault(n.jurisdiction or "unknown", []).append(n.name)
    out = ["digraph sovereign {", "  rankdir=LR;", '  node [shape=box, style="rounded"];']
    for i, (place, names) in enumerate(sorted(by_place.items())):
        out.append(f"  subgraph cluster_{i} {{")
        out.append(f"    label={_q(place)};")
        out.extend(f"    {_q(n)};" for n in names)
        out.append("  }")
    for f in sorted(arch.flows, key=lambda x: x.label):
        style = ' color="red", fontcolor="red", style="dashed"' if f in bad else ""
        out.append(f"  {_q(f.src)} -> {_q(f.dst)} [label={_q(f.data_class)}{style}];")
    out.append("}")
    return "\n".join(out) + "\n"


def _q(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_mermaid(arch: Architecture, report: Report | None = None) -> str:
    """Mermaid flowchart with one subgraph per jurisdiction. Flows with an error are drawn in red."""
    bad = _bad_flows(report)
    ids = {n: f"n{i}" for i, n in enumerate(sorted(arch.nodes))}
    by_place: dict[str, list[str]] = {}
    for name in sorted(arch.nodes):
        by_place.setdefault(arch.nodes[name].jurisdiction or "unknown", []).append(name)
    out = ["flowchart LR"]
    for i, (place, names) in enumerate(sorted(by_place.items())):
        out.append(f"  subgraph J{i}[{_m(place)}]")
        out.extend(f"    {ids[n]}[{_m(n)}]" for n in names)
        out.append("  end")
    red: list[int] = []
    flows = sorted((f for f in arch.flows if f.src in ids and f.dst in ids), key=lambda x: x.label)
    for i, f in enumerate(flows):
        out.append(f"  {ids[f.src]} -->|{_m(f.data_class, bare=True)}| {ids[f.dst]}")
        if f in bad:
            red.append(i)
    if red:
        out.append(f"  linkStyle {','.join(map(str, red))} stroke:#d00,stroke-width:2px")
    return "\n".join(out) + "\n"


def _m(text: str, *, bare: bool = False) -> str:
    safe = text.replace('"', "'")
    return safe if bare and safe.replace("-", "").replace("_", "").replace(" ", "").isalnum() else f'"{safe}"'


def to_sarif(report: Report, uri: str = "architecture.json") -> dict[str, Any]:
    """SARIF 2.1.0, so findings show up in code-scanning tools. Each result is located by the flow or node it concerns."""
    used = sorted({f.rule for f in report.findings})
    results = []
    for f in report.findings:
        name = f.flow.label if f.flow else f.node
        results.append({
            "ruleId": f.rule, "level": "error" if f.severity == "error" else "warning",
            "message": {"text": f.reason + (f" Fix: {f.hint}." if f.hint else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}},
                           "logicalLocations": [{"name": name, "kind": "flow" if f.flow else "node"}]}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "sovereign.map", "version": __version__,
                                       "rules": [{"id": r, "shortDescription": {"text": RULES.get(r, r)}} for r in used]}},
                  "results": results, "properties": {"fingerprint": report.fingerprint}}],
    }
