"""Command line. Exit codes: 0 pass, 1 the gate was hit (errors, or new errors for ``diff``), 2 bad input.

    sovereign-map check ARCHITECTURE POLICY [--format text|json|markdown|sarif] [--fail-on error|warning|never] [--lint]
    sovereign-map diff BEFORE AFTER POLICY [--fail-on-new]
    sovereign-map graph ARCHITECTURE [POLICY] --format dot|mermaid
    sovereign-map exposure ARCHITECTURE
    sovereign-map egress ARCHITECTURE --home AE
    sovereign-map paths ARCHITECTURE DATA_CLASS SRC DST
    sovereign-map fingerprint ARCHITECTURE POLICY
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .diff import diff
from .engine import evaluate
from .graph import cross_border, egress, exposure, paths
from .model import Architecture, fingerprint
from .policy import Policy
from .render import to_dot, to_markdown, to_mermaid, to_sarif, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sovereign-map", description="Check AI data flows against residency, control and transfer rules you define. Not legal advice.")
    parser.add_argument("--version", action="version", version=f"sovereign.map {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("check", help="evaluate an architecture against a policy")
    p.add_argument("architecture")
    p.add_argument("policy")
    p.add_argument("--format", choices=["text", "json", "markdown", "sarif"], default="text")
    p.add_argument("--fail-on", choices=["error", "warning", "never"], default="error", help="what makes the exit code 1 (default: error)")
    p.add_argument("--lint", action="store_true", help="also warn about orphan nodes, unknown locations, unruled classes and unused rules")
    p = sub.add_parser("diff", help="compare two architectures under one policy")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("policy")
    p.add_argument("--fail-on-new", action="store_true", help="exit 1 when the change adds an error")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("graph", help="draw the architecture")
    p.add_argument("architecture")
    p.add_argument("policy", nargs="?", help="when given, flows with an error are drawn in red")
    p.add_argument("--format", choices=["dot", "mermaid"], default="mermaid")
    p = sub.add_parser("exposure", help="jurisdictions each data class touches, and every cross-border crossing")
    p.add_argument("architecture")
    p = sub.add_parser("egress", help="flows that leave the home jurisdiction")
    p.add_argument("architecture")
    p.add_argument("--home", required=True)
    p = sub.add_parser("paths", help="every route a data class can take between two nodes")
    p.add_argument("architecture")
    p.add_argument("data_class")
    p.add_argument("src")
    p.add_argument("dst")
    p = sub.add_parser("fingerprint", help="the SHA-256 that ties a report to its exact inputs")
    p.add_argument("architecture")
    p.add_argument("policy")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except (ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _run(a: argparse.Namespace) -> int:
    c = a.command
    if c == "check":
        arch, policy = Architecture.load(a.architecture), Policy.load(a.policy)
        report = evaluate(arch, policy, lint=a.lint)
        if a.format == "json":
            print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        elif a.format == "markdown":
            print(to_markdown(report, arch), end="")
        elif a.format == "sarif":
            print(json.dumps(to_sarif(report, a.architecture), indent=2, ensure_ascii=False))
        else:
            print(to_text(report))
        if a.fail_on == "never":
            return 0
        return 1 if report.errors or (a.fail_on == "warning" and report.warnings) else 0
    if c == "diff":
        d = diff(Architecture.load(a.before), Architecture.load(a.after), Policy.load(a.policy))
        if a.json:
            print(json.dumps(d.to_dict(), indent=2, ensure_ascii=False))
        else:
            for f in d.new:
                print(f"NEW      {f.severity} {f.rule}: {f.reason}")
            for f in d.resolved:
                print(f"RESOLVED {f.severity} {f.rule}: {f.reason}")
            for cls, places in d.exposure_added.items():
                print(f"EXPOSED  {cls} now also touches {', '.join(places)}")
            for flow in d.egress_added:
                print(f"EGRESS   {flow.label}")
            print("WORSE" if d.worse else "NOT WORSE")
        return 1 if a.fail_on_new and d.worse else 0
    if c == "graph":
        arch = Architecture.load(a.architecture)
        marked = evaluate(arch, Policy.load(a.policy)) if a.policy else None
        print((to_dot if a.format == "dot" else to_mermaid)(arch, marked), end="")
    elif c == "exposure":
        arch = Architecture.load(a.architecture)
        print(json.dumps({"exposure": exposure(arch), "cross_border": [{"from": x, "to": y, "data_classes": z}
                                                                       for (x, y), z in cross_border(arch).items()]}, indent=2))
    elif c == "egress":
        arch = Architecture.load(a.architecture)
        print(json.dumps([f.label for f in egress(arch, None, a.home)], indent=2))
    elif c == "paths":
        arch = Architecture.load(a.architecture)
        found = paths(arch, a.data_class, a.src, a.dst)
        print(json.dumps(found))
        return 0 if found else 1
    else:
        arch, policy = Architecture.load(a.architecture), Policy.load(a.policy)
        print(fingerprint(arch, policy.to_dict()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
