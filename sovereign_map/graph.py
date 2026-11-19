"""Questions about an architecture that need no policy: where does each class go, what leaves home, who can reach whom."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping

from .labels import covers, is_unknown, same_jurisdiction
from .model import Architecture, Flow, Node, as_architecture


def exposure(nodes: Architecture | Mapping[str, Node], flows: Iterable[Flow] | None = None) -> dict[str, list[str]]:
    """For each data class, the sorted jurisdictions it touches. Flows that name an unknown node are skipped here
    (``check`` and ``audit`` report them)."""
    arch = as_architecture(nodes, flows)
    touched: dict[str, set[str]] = defaultdict(set)
    for flow in arch.flows:
        for end in (flow.src, flow.dst):
            if end in arch.nodes:
                touched[flow.data_class].add(arch.nodes[end].jurisdiction)
    return {k: sorted(v) for k, v in sorted(touched.items())}


def egress(nodes: Architecture | Mapping[str, Node], flows: Iterable[Flow] | None, home: str, *,
           groups: Mapping[str, frozenset[str]] | None = None, hierarchical: bool = True) -> list[Flow]:
    """Flows whose source is inside the home jurisdiction and whose destination is not. ``home`` may be a group such as GCC. A destination
    with an unknown location is not inside home, so it counts as leaving."""
    arch = as_architecture(nodes, flows)

    def inside(name: str) -> bool:
        return covers(home, arch.nodes[name].jurisdiction, groups, hierarchical=hierarchical)

    return [f for f in arch.flows if f.src in arch.nodes and f.dst in arch.nodes and inside(f.src) and not inside(f.dst)]


def cross_border(arch: Architecture, *, hierarchical: bool = True) -> dict[tuple[str, str], list[str]]:
    """Every pair (from jurisdiction, to jurisdiction) that data crosses, with the data classes that cross it. Moves between regions
    of one jurisdiction (AE-DXB to AE-AUH) are not crossings."""
    matrix: dict[tuple[str, str], set[str]] = defaultdict(set)
    for f in arch.flows:
        a, b = arch.nodes.get(f.src), arch.nodes.get(f.dst)
        if a and b and not same_jurisdiction(a.jurisdiction, b.jurisdiction, hierarchical=hierarchical):
            matrix[(a.jurisdiction, b.jurisdiction)].add(f.data_class)
    return {k: sorted(v) for k, v in sorted(matrix.items())}


def holders(arch: Architecture) -> dict[str, dict[str, list[str]]]:
    """For each node, the data classes it receives and the classes it sends."""
    table: dict[str, dict[str, set[str]]] = {n: {"receives": set(), "sends": set()} for n in arch.nodes}
    for f in arch.flows:
        if f.dst in table:
            table[f.dst]["receives"].add(f.data_class)
        if f.src in table:
            table[f.src]["sends"].add(f.data_class)
    return {n: {k: sorted(v) for k, v in d.items()} for n, d in sorted(table.items())}


def reach(arch: Architecture, start: str, data_class: str | None = None) -> list[str]:
    """Nodes that data leaving ``start`` can arrive at by following flows (of one class when given). Excludes ``start`` unless
    a cycle returns to it."""
    out: dict[str, list[str]] = defaultdict(list)
    for f in arch.flows:
        if data_class is None or f.data_class == data_class:
            out[f.src].append(f.dst)
    seen: set[str] = set()
    stack = list(out.get(start, []))
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(out.get(n, []))
    return sorted(seen)


def paths(arch: Architecture, data_class: str, src: str, dst: str, *, limit: int = 100) -> list[list[str]]:
    """Simple paths from ``src`` to ``dst`` along flows of ``data_class``, shortest first, at most ``limit`` of them."""
    out: dict[str, list[str]] = defaultdict(list)
    for f in arch.flows:
        if f.data_class == data_class:
            out[f.src].append(f.dst)
    found: list[list[str]] = []

    def walk(node: str, trail: list[str]) -> None:
        if len(found) >= limit:
            return
        if node == dst and len(trail) > 1:
            found.append(list(trail))
            return
        for nxt in sorted(set(out.get(node, []))):
            if nxt not in trail or (nxt == dst and node != dst):
                trail.append(nxt)
                walk(nxt, trail)
                trail.pop()

    walk(src, [src])
    return sorted(found, key=lambda p: (len(p), p))


def orphans(arch: Architecture) -> list[str]:
    """Declared nodes that no flow touches. Often a sign that a flow is missing from the model."""
    used = {x for f in arch.flows for x in (f.src, f.dst)}
    return sorted(n for n in arch.nodes if n not in used)


def sinks(arch: Architecture) -> list[str]:
    """Nodes that receive data and send none onward."""
    sends = {f.src for f in arch.flows}
    return sorted({f.dst for f in arch.flows if f.dst in arch.nodes} - sends)


def unknown_locations(arch: Architecture) -> list[str]:
    return sorted(n.name for n in arch.nodes.values() if is_unknown(n.jurisdiction))
