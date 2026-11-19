"""The architecture model: nodes in jurisdictions and the flows of named data classes between them."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .labels import is_unknown


def _strings(value: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(value)))


@dataclass(frozen=True)
class Node:
    """A system that stores or processes data.

    ``jurisdiction`` is where it runs. ``operator`` is the jurisdiction whose law controls the party that operates it, which for a
    foreign-owned cloud region differs from where the hardware sits. Leave it empty when you do not know; rules about control then
    report "not declared" instead of guessing. ``kind`` (for example ``model``, ``datastore``, ``client``) lets the tool suggest
    compliant alternatives that already exist in your architecture."""

    name: str
    jurisdiction: str
    operator: str = ""
    kind: str = ""
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tags", _strings(self.tags))

    @property
    def location_known(self) -> bool:
        return not is_unknown(self.jurisdiction)


@dataclass(frozen=True)
class Flow:
    """Data of one class moving from ``src`` to ``dst``. ``mechanism`` names the legal or contractual basis you rely on for a
    cross-border move ("scc", "adequacy", "consent": your words, matched against the policy). ``protections`` are technical
    measures in place on this flow ("tls", "customer-key", "tokenized")."""

    src: str
    dst: str
    data_class: str
    mechanism: str = ""
    protections: tuple[str, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "protections", _strings(self.protections))

    @property
    def label(self) -> str:
        return f"{self.src} -> {self.dst} [{self.data_class}]"


@dataclass(frozen=True)
class Finding:
    """One thing wrong or suspicious. ``rule`` says which check produced it, ``severity`` is ``error`` or ``warning``."""

    flow: Flow | None
    reason: str
    rule: str = "processing"
    severity: str = "error"
    node: str = ""
    hint: str = ""

    def key(self) -> tuple[str, ...]:
        """Identity used to compare two runs: the same rule on the same node and the same flow (including how the flow is protected)
        is the same finding, whatever its wording."""
        f = self.flow
        if f is None:
            return (self.rule, self.node)
        return (self.rule, self.node, f.src, f.dst, f.data_class, f.mechanism, ",".join(f.protections))

    def sort_key(self) -> tuple[int, tuple[str, ...], str, str, str]:
        """A total order, so output never depends on set or hash ordering: severity, identity, then the flow note, reason and hint."""
        return (0 if self.severity == "error" else 1, self.key(), self.flow.note if self.flow else "", self.reason, self.hint)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"rule": self.rule, "severity": self.severity, "reason": self.reason}
        if self.flow:
            out["flow"] = {"src": self.flow.src, "dst": self.flow.dst, "data_class": self.flow.data_class}
        if self.node:
            out["node"] = self.node
        if self.hint:
            out["hint"] = self.hint
        return out


Violation = Finding  # the name used up to 0.1


class Architecture:
    """Nodes by name and a duplicate-free tuple of flows. Build one with ``Architecture.of`` or ``Architecture.from_dict``."""

    def __init__(self, nodes: Mapping[str, Node], flows: Iterable[Flow]) -> None:
        for key, node in nodes.items():
            if key != node.name:
                raise ValueError(f"node registered as {key!r} is named {node.name!r}")
        self.nodes: dict[str, Node] = dict(nodes)
        seen: dict[Flow, None] = {}
        for f in flows:
            seen.setdefault(f, None)
        self.flows: tuple[Flow, ...] = tuple(seen)

    @classmethod
    def of(cls, nodes: Iterable[Node], flows: Iterable[Flow]) -> Architecture:
        table: dict[str, Node] = {}
        for n in nodes:
            if not n.name:
                raise ValueError("a node needs a name")
            if n.name in table and table[n.name] != n:
                raise ValueError(f"node {n.name!r} is declared twice with different details")
            table[n.name] = n
        return cls(table, flows)

    # serialization -------------------------------------------------------------------------------------------------------------
    _NODE_KEYS = {"name", "jurisdiction", "operator", "kind", "tags"}
    _FLOW_KEYS = {"src", "dst", "data_class", "mechanism", "protections", "note"}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Architecture:
        """Strict: unknown keys are errors, because a misspelt ``jurisdication`` would otherwise silently defeat a rule."""
        _no_extra(data, {"nodes", "flows", "name"}, "architecture")
        raw_nodes, raw_flows = data.get("nodes", []), data.get("flows", [])
        if not isinstance(raw_nodes, list) or not isinstance(raw_flows, list):
            raise ValueError("architecture: nodes and flows must be lists")
        nodes: list[Node] = []
        for i, item in enumerate(raw_nodes):
            where = f"nodes[{i}]"
            _no_extra(item, cls._NODE_KEYS, where)
            nodes.append(Node(_text(item, "name", where, required=True), _text(item, "jurisdiction", where, required=True),
                              _text(item, "operator", where), _text(item, "kind", where), tuple(_list(item, "tags", where))))
        flows: list[Flow] = []
        for i, item in enumerate(raw_flows):
            where = f"flows[{i}]"
            _no_extra(item, cls._FLOW_KEYS, where)
            flows.append(Flow(_text(item, "src", where, required=True), _text(item, "dst", where, required=True),
                              _text(item, "data_class", where, required=True), _text(item, "mechanism", where),
                              tuple(_list(item, "protections", where)), _text(item, "note", where)))
        return cls.of(nodes, flows)

    def to_dict(self) -> dict[str, Any]:
        """Canonical form: sorted, with defaults left out. Two architectures with the same content give the same dict."""
        nodes = []
        for n in sorted(self.nodes.values(), key=lambda x: x.name):
            d: dict[str, Any] = {"name": n.name, "jurisdiction": n.jurisdiction}
            if n.operator:
                d["operator"] = n.operator
            if n.kind:
                d["kind"] = n.kind
            if n.tags:
                d["tags"] = list(n.tags)
            nodes.append(d)
        flows = []
        for f in sorted(self.flows, key=lambda x: (x.src, x.dst, x.data_class, x.mechanism, x.protections, x.note)):
            fd: dict[str, Any] = {"src": f.src, "dst": f.dst, "data_class": f.data_class}
            if f.mechanism:
                fd["mechanism"] = f.mechanism
            if f.protections:
                fd["protections"] = list(f.protections)
            if f.note:
                fd["note"] = f.note
            flows.append(fd)
        return {"nodes": nodes, "flows": flows}

    @classmethod
    def load(cls, path: str | Path) -> Architecture:
        return cls.from_dict(_read_json(path))

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Architecture) and self.to_dict() == other.to_dict()

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"Architecture({len(self.nodes)} nodes, {len(self.flows)} flows)"


def as_architecture(nodes: Architecture | Mapping[str, Node], flows: Iterable[Flow] | None = None) -> Architecture:
    """Accept either an Architecture or the ``(nodes dict, flows)`` pair that 0.1 used."""
    if isinstance(nodes, Architecture):
        return nodes
    return Architecture(nodes, flows or ())


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(arch: Architecture, policy_dict: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical architecture and policy. Equal inputs give an equal fingerprint on any machine and any Python,
    whatever order the nodes, flows and rules were written in, so a report can be tied to exactly what was checked."""
    payload = canonical_json({"architecture": arch.to_dict(), "policy": policy_dict})
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


# helpers ---------------------------------------------------------------------------------------------------------------------
def _read_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON ({exc})") from exc
    except OSError as exc:
        raise ValueError(f"{path}: cannot read ({exc.strerror})") from exc


def _no_extra(item: Any, allowed: set[str], where: str) -> None:
    if not isinstance(item, Mapping):
        raise ValueError(f"{where}: expected an object")
    extra = sorted(set(item) - allowed)
    if extra:
        raise ValueError(f"{where}: unknown key {extra[0]!r} (allowed: {', '.join(sorted(allowed))})")


def _text(item: Mapping[str, Any], key: str, where: str, *, required: bool = False) -> str:
    value = item.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{where}.{key}: expected a string")
    if required and not value.strip():
        raise ValueError(f"{where}.{key}: required")
    return value.strip()


def _list(item: Mapping[str, Any], key: str, where: str) -> list[str]:
    value = item.get(key, [])
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{where}.{key}: expected a list of strings")
    return [x.strip() for x in value]
