"""Measures the engine and prints the numbers the README quotes. Run: python examples/evaluate.py

The cases are seeded random architectures, so every figure is reproducible. Agreement is with a second implementation in
tests/test_properties.py, written separately from the definitions. It shows the engine does what the definitions say. It does not
show that the definitions match any law: the rules are yours."""
from __future__ import annotations

import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_properties import oracle, triples  # noqa: E402

from sovereign_map import Architecture, Flow, Node, Policy, diff, evaluate  # noqa: E402
from sovereign_map.synthetic import random_case  # noqa: E402


def main() -> int:
    cases = 3000
    agree = findings = 0
    by_rule: dict[str, int] = {}
    for seed in range(cases):
        arch, policy = random_case(seed)
        report = evaluate(arch, policy)
        want = oracle(arch, policy)
        agree += triples(report) == want
        findings += len(report.findings)
        for f in report.findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    print(f"oracle agreement        {agree}/{cases} random cases, {findings} findings across them")
    print("findings by rule        " + ", ".join(f"{k} {v}" for k, v in sorted(by_rule.items())))

    policy = Policy(processing={"personal": frozenset({"AE"})})
    caught = trials = 0
    for seed in range(1000):
        rng = random.Random(seed)
        nodes = [Node(f"n{i}", rng.choice(["AE", "AE-DXB", "AE-AUH"])) for i in range(6)]
        flows = [Flow(f"n{rng.randrange(6)}", f"n{rng.randrange(6)}", "personal") for _ in range(8)]
        moved = rng.randrange(6)
        nodes[moved] = Node(f"n{moved}", rng.choice(["US", "US-East", "DE", "SG", "unknown", "AEE"]))
        touching = {f for f in flows if f"n{moved}" in (f.src, f.dst)}
        if not touching:
            continue
        trials += 1
        flagged = {f.flow for f in evaluate(Architecture.of(nodes, flows), policy).findings if f.node == f"n{moved}"}
        caught += touching <= flagged
    print(f"mutation detection      {caught}/{trials} out-of-bounds moves caught on every flow touching the moved node")

    stable = 0
    for seed in range(1000):
        arch, pol = random_case(seed)
        rng = random.Random(seed)
        nodes, flows = list(arch.nodes.values()), list(arch.flows)
        rng.shuffle(nodes)
        rng.shuffle(flows)
        a, b = evaluate(arch, pol), evaluate(Architecture.of(nodes, flows), pol)
        stable += a.findings == b.findings and a.fingerprint == b.fingerprint
    print(f"order independence      {stable}/1000 shuffles gave identical findings and fingerprint")

    rng = random.Random(1)
    places = ["AE", "AE-DXB", "SA", "DE", "US", "SG", "unknown"]
    n_nodes, n_flows = 2000, 20000
    big = Architecture.of([Node(f"n{i}", rng.choice(places), rng.choice(["AE", "US", "DE"])) for i in range(n_nodes)],
                          [Flow(f"n{rng.randrange(n_nodes)}", f"n{rng.randrange(n_nodes)}", rng.choice(["personal", "health", "telemetry"]))
                           for _ in range(n_flows)])
    big_policy = Policy(processing={"personal": frozenset({"AE", "SA"}), "health": frozenset({"AE"})}, control={"personal": frozenset({"AE"})},
                        classes={"health": "personal"}, home="AE")
    start = time.perf_counter()
    report = evaluate(big, big_policy)
    elapsed = time.perf_counter() - start
    start = time.perf_counter()
    diff(big, big, big_policy)
    diff_elapsed = time.perf_counter() - start
    print(f"scale                   {n_flows} flows over {n_nodes} nodes: {len(report.findings)} findings in {elapsed:.2f}s; "
          f"diff of two such architectures in {diff_elapsed:.2f}s (this machine)")
    return 0 if agree == cases and caught == trials and stable == 1000 else 1


if __name__ == "__main__":
    sys.exit(main())
