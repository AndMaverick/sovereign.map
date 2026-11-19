"""The rules you define. sovereign.map enforces them. It does not know what any law requires."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .labels import BUILTIN_GROUPS
from .model import _list, _no_extra, _read_json, _text


@dataclass(frozen=True)
class TransferRule:
    """What a cross-border move of a data class needs.

    ``mechanisms``: the flow must name one of these in its ``mechanism`` (empty means none is needed).
    ``free_within``: group names; a flow whose two ends are both inside one of these groups needs nothing.
    ``protections``: protections the flow must declare."""

    mechanisms: frozenset[str] = frozenset()
    free_within: tuple[str, ...] = ()
    protections: frozenset[str] = frozenset()


def _set(rules: Mapping[str, Any]) -> dict[str, frozenset[str]]:
    return {k: frozenset(v) for k, v in rules.items()}


@dataclass
class Policy:
    """Residency, control and transfer rules over data classes.

    processing   data class -> jurisdictions it may be processed in (a class with no entry is unrestricted)
    deny         data class -> jurisdictions it may never touch
    control      data class -> jurisdictions whose law may control the operator of a node that handles it
    transfer     data class -> TransferRule for cross-border flows
    classes      child class -> parent class; a flow of the child must satisfy the parent's rules too (health -> personal)
    open         classes you have decided are unrestricted, so the audit does not warn about them
    groups       your own named sets of jurisdictions, added to or overriding the built-in EU, EEA, GCC and ASEAN
    home         your home jurisdiction, used to list egress
    hierarchical whether "US" also covers "US-East" (default yes)"""

    processing: dict[str, frozenset[str]] = field(default_factory=dict)
    deny: dict[str, frozenset[str]] = field(default_factory=dict)
    control: dict[str, frozenset[str]] = field(default_factory=dict)
    transfer: dict[str, TransferRule] = field(default_factory=dict)
    classes: dict[str, str] = field(default_factory=dict)
    open: frozenset[str] = frozenset()
    groups: dict[str, frozenset[str]] = field(default_factory=dict)
    home: str = ""
    hierarchical: bool = True
    name: str = ""

    def __post_init__(self) -> None:
        for child in self.classes:
            chain = [child]
            while chain[-1] in self.classes:
                nxt = self.classes[chain[-1]]
                if nxt in chain:
                    raise ValueError(f"classes: {' -> '.join([*chain, nxt])} is a cycle")
                chain.append(nxt)

    @classmethod
    def from_allowed(cls, allowed: Mapping[str, Any]) -> Policy:
        """The 0.1 form: a plain mapping of data class to the jurisdictions it may be processed in."""
        return cls(processing={k: frozenset(v) for k, v in allowed.items()})

    def lineage(self, data_class: str) -> list[str]:
        """The class followed by its parents, nearest first."""
        out = [data_class]
        while out[-1] in self.classes:
            out.append(self.classes[out[-1]])
        return out

    def ruled_classes(self) -> frozenset[str]:
        return frozenset([*self.processing, *self.deny, *self.control, *self.transfer])

    def all_groups(self) -> dict[str, frozenset[str]]:
        merged = dict(BUILTIN_GROUPS)
        merged.update(self.groups)
        return merged

    # serialization -------------------------------------------------------------------------------------------------------------
    _KEYS = {"name", "home", "hierarchical", "groups", "classes", "open", "processing", "deny", "control", "transfer"}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        _no_extra(data, cls._KEYS, "policy")
        sets: dict[str, dict[str, frozenset[str]]] = {}
        for key in ("processing", "deny", "control", "groups"):
            raw = data.get(key, {})
            if not isinstance(raw, Mapping):
                raise ValueError(f"policy.{key}: expected an object of lists")
            sets[key] = {}
            for name, members in raw.items():
                if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
                    raise ValueError(f"policy.{key}.{name}: expected a list of strings")
                sets[key][name] = frozenset(m.strip() for m in members)
        raw_classes = data.get("classes", {})
        if not isinstance(raw_classes, Mapping) or not all(isinstance(v, str) for v in raw_classes.values()):
            raise ValueError("policy.classes: expected an object mapping each class to its parent class")
        transfer: dict[str, TransferRule] = {}
        raw_transfer = data.get("transfer", {})
        if not isinstance(raw_transfer, Mapping):
            raise ValueError("policy.transfer: expected an object")
        for name, rule in raw_transfer.items():
            where = f"policy.transfer.{name}"
            _no_extra(rule, {"mechanisms", "free_within", "protections"}, where)
            transfer[name] = TransferRule(frozenset(m.casefold() for m in _list(rule, "mechanisms", where)),
                                          tuple(_list(rule, "free_within", where)),
                                          frozenset(p.casefold() for p in _list(rule, "protections", where)))
        hier = data.get("hierarchical", True)
        if not isinstance(hier, bool):
            raise ValueError("policy.hierarchical: expected true or false")
        return cls(sets["processing"], sets["deny"], sets["control"], transfer, dict(raw_classes),
                   frozenset(_list(data, "open", "policy")), sets["groups"], _text(data, "home", "policy"), hier,
                   _text(data, "name", "policy"))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.name:
            out["name"] = self.name
        if self.home:
            out["home"] = self.home
        if not self.hierarchical:
            out["hierarchical"] = False
        for key in ("processing", "deny", "control", "groups"):
            table = getattr(self, key)
            if table:
                out[key] = {k: sorted(v) for k, v in sorted(table.items())}
        if self.classes:
            out["classes"] = dict(sorted(self.classes.items()))
        if self.open:
            out["open"] = sorted(self.open)
        if self.transfer:
            out["transfer"] = {k: {"mechanisms": sorted(r.mechanisms), "free_within": sorted(r.free_within),
                                   "protections": sorted(r.protections)} for k, r in sorted(self.transfer.items())}
        return out

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        return cls.from_dict(_read_json(path))

    def dump(self, path: str | Path) -> None:
        import json
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
