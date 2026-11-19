"""Seeded random architectures and policies, for property tests and for measuring the engine. The same seed gives the same case."""
from __future__ import annotations

import random

from .model import Architecture, Flow, Node
from .policy import Policy, TransferRule

PLACES = ["AE", "AE-DXB", "SA", "EU", "DE", "FR", "US", "US-East", "SG", "ID", "IN", "unknown"]
CLASSES = ["personal", "health", "financial", "telemetry", "public", "model-weights"]
OPERATORS = ["AE", "SA", "US", "DE", "SG", ""]
MECHANISMS = ["", "scc", "adequacy", "consent", "bilateral-agreement"]
PROTECTIONS = ["tls", "customer-key", "tokenized"]


def random_case(seed: int, *, nodes: int = 8, flows: int = 14) -> tuple[Architecture, Policy]:
    rng = random.Random(seed)
    node_list = [Node(f"n{i}", rng.choice(PLACES), rng.choice(OPERATORS), rng.choice(["", "model", "datastore", "service"])) for i in range(nodes)]
    flow_list = []
    for _ in range(flows):
        src, dst = rng.randrange(nodes), rng.randrange(nodes + 1)  # nodes + 1 sometimes names a node that does not exist
        flow_list.append(Flow(f"n{src}", f"n{dst}", rng.choice(CLASSES), rng.choice(MECHANISMS),
                              tuple(rng.sample(PROTECTIONS, rng.randrange(len(PROTECTIONS) + 1)))))
    arch = Architecture.of(node_list, flow_list)
    processing = {c: frozenset(rng.sample(PLACES[:-1], rng.randrange(1, 6))) for c in CLASSES if rng.random() < 0.6}
    deny = {c: frozenset(rng.sample(PLACES[:-1], rng.randrange(1, 3))) for c in CLASSES if rng.random() < 0.25}
    control = {c: frozenset(rng.sample(OPERATORS[:-1], rng.randrange(1, 4))) for c in CLASSES if rng.random() < 0.25}
    transfer = {c: TransferRule(frozenset(rng.sample(MECHANISMS[1:], rng.randrange(0, 3))), tuple(rng.sample(["EU", "GCC"], rng.randrange(0, 2))),
                                frozenset(rng.sample(PROTECTIONS, rng.randrange(0, 3)))) for c in CLASSES if rng.random() < 0.3}
    classes = {"health": "personal"} if rng.random() < 0.5 else {}
    return arch, Policy(processing, deny, control, transfer, classes, home="AE")
