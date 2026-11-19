"""Jurisdiction labels: how a node's label is matched against a rule entry.

An entry in a rule covers a label when any of these holds (all comparisons ignore case):

* the entry equals the label ("AE" covers "AE");
* the label is a sub-region of the entry, written with a ``-``, ``/`` or ``:`` separator ("US" covers "US-East", "AE" covers "AE-DXB");
  this can be switched off with ``hierarchical=False``;
* the entry names a group and any member of the group covers the label ("GCC" covers "AE-DXB"); groups may contain other groups;
* the entry is ``*`` and the label is a known location.

Because of the sub-region rule, the part of a label before its first separator is its jurisdiction: AE-DXB and AE-AUH are both in AE,
and a flow between them is not cross-border. Set ``hierarchical=False`` for labels that use dashes as part of a name ("on-prem").

A label that is empty, ``?`` or ``unknown`` is covered by nothing, not even ``*``. A restricted data class sent to a node whose
location is unknown is therefore always a finding. The built-in groups below are plain geography and membership lists for
convenience. They are not a statement of what any law requires, and you can override any of them in a policy."""
from __future__ import annotations

from collections.abc import Iterable, Mapping

SEPARATORS = "-/:"
UNKNOWN_LABELS = frozenset({"", "?", "unknown"})

EU27 = frozenset(["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"])

BUILTIN_GROUPS: dict[str, frozenset[str]] = {
    "EU": EU27,
    "EEA": EU27 | frozenset({"IS", "LI", "NO"}),
    "GCC": frozenset(["AE", "BH", "KW", "OM", "QA", "SA"]),
    "ASEAN": frozenset(["BN", "KH", "ID", "LA", "MY", "MM", "PH", "SG", "TH", "VN"]),
}


def root(label: str, *, hierarchical: bool = True) -> str:
    """The jurisdiction part of a label: "US-East" is in "US". With ``hierarchical=False`` the whole label is the jurisdiction."""
    text = label.strip().casefold()
    if hierarchical:
        for i, ch in enumerate(text):
            if ch in SEPARATORS:
                return text[:i]
    return text


def same_jurisdiction(a: str, b: str, *, hierarchical: bool = True) -> bool:
    """Whether two labels are the same jurisdiction, so a flow between them is not cross-border (AE-DXB to AE-AUH is not)."""
    return root(a, hierarchical=hierarchical) == root(b, hierarchical=hierarchical)


def is_unknown(label: str) -> bool:
    return label.strip().casefold() in UNKNOWN_LABELS


def covers(entry: str, label: str, groups: Mapping[str, frozenset[str]] | None = None, *, hierarchical: bool = True) -> bool:
    """Whether the rule entry covers the node label (see the module docstring)."""
    return _covers(entry.strip().casefold(), label.strip().casefold(), _fold(groups), hierarchical, frozenset())


def covered_by_any(entries: frozenset[str] | set[str], label: str, groups: Mapping[str, frozenset[str]] | None = None, *,
                   hierarchical: bool = True) -> bool:
    folded = _fold(groups)
    wanted = label.strip().casefold()
    return any(_covers(e.strip().casefold(), wanted, folded, hierarchical, frozenset()) for e in entries)


def group_names(groups: Mapping[str, frozenset[str]] | None = None) -> frozenset[str]:
    return frozenset(_fold(groups))


def _fold(groups: Mapping[str, frozenset[str]] | None) -> dict[str, frozenset[str]]:
    merged = {k.casefold(): frozenset(m.casefold() for m in v) for k, v in BUILTIN_GROUPS.items()}
    for name, members in (groups or {}).items():
        merged[name.strip().casefold()] = frozenset(m.strip().casefold() for m in members)
    return merged


def _covers(entry: str, label: str, groups: dict[str, frozenset[str]], hierarchical: bool, seen: frozenset[str]) -> bool:
    if label in UNKNOWN_LABELS or not entry:
        return False
    if entry == "*":
        return True
    if entry == label:
        return True
    if hierarchical and label.startswith(entry) and label[len(entry)] in SEPARATORS:
        return True
    members = groups.get(entry)
    if members is not None and entry not in seen:
        nxt = seen | {entry}
        return any(_covers(m, label, groups, hierarchical, nxt) for m in members)
    return False


class Matcher:
    """``covers`` for one set of groups, with the group table folded once and answers remembered. The engine builds one per run."""

    def __init__(self, groups: Mapping[str, frozenset[str]] | None = None, *, hierarchical: bool = True) -> None:
        self._groups = _fold(groups)
        self._hierarchical = hierarchical
        self._memo: dict[tuple[str, str], bool] = {}
        self.scratch: dict[tuple[str, str, frozenset[str]], list[str]] = {}  # the engine remembers compliant alternatives here for this run

    def covers(self, entry: str, label: str) -> bool:
        key = (entry, label)
        hit = self._memo.get(key)
        if hit is None:
            hit = self._memo[key] = _covers(entry.strip().casefold(), label.strip().casefold(), self._groups, self._hierarchical, frozenset())
        return hit

    def any(self, entries: Iterable[str], label: str) -> bool:
        return any(self.covers(e, label) for e in entries)
