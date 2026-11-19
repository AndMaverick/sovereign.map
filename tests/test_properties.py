"""Properties over seeded random cases, and agreement with a second implementation written separately and kept deliberately simple."""
import random
import unittest

from sovereign_map import Architecture, Flow, Node, Policy, check, diff, evaluate
from sovereign_map.synthetic import random_case

N = 1500
GROUPS = {"eu": {"de", "fr"}, "gcc": {"ae", "sa"}}  # only the members the generator can produce


def inside(entry: str, label: str) -> bool:
    e, v = entry.lower(), label.lower()
    if v in ("", "?", "unknown"):
        return False
    if e == v or v.startswith(e + "-"):
        return True
    return any(inside(m, label) for m in GROUPS.get(e, ()))


def oracle(arch: Architecture, policy: Policy) -> set[tuple[str, str, str]]:
    """The expected (rule, node, flow label) triples, written straight from the definitions."""
    expected: set[tuple[str, str, str]] = set()
    for f in arch.flows:
        if f.src not in arch.nodes or f.dst not in arch.nodes:
            expected.add(("unknown-node", "", f.label))
            continue
        a, b = arch.nodes[f.src], arch.nodes[f.dst]
        chain = [f.data_class]
        while chain[-1] in policy.classes:
            chain.append(policy.classes[chain[-1]])
        for cls in chain:
            for n in (a, b):
                if cls in policy.processing and not any(inside(e, n.jurisdiction) for e in policy.processing[cls]):
                    expected.add(("processing", n.name, f.label))
                if cls in policy.deny and any(inside(e, n.jurisdiction) for e in policy.deny[cls]):
                    expected.add(("deny", n.name, f.label))
                if cls in policy.control:
                    if n.operator == "":
                        expected.add(("control-undeclared", n.name, f.label))
                    elif not any(inside(e, n.operator) for e in policy.control[cls]):
                        expected.add(("control", n.name, f.label))
            rule = policy.transfer.get(cls)
            if rule and a.jurisdiction.lower().split("-")[0] != b.jurisdiction.lower().split("-")[0]:
                if any(inside(g, a.jurisdiction) and inside(g, b.jurisdiction) for g in rule.free_within):
                    continue
                if rule.mechanisms and f.mechanism.lower() not in rule.mechanisms:
                    expected.add(("transfer", "", f.label))
                if rule.protections - set(f.protections):
                    expected.add(("protection", "", f.label))
    return expected


def triples(report) -> set[tuple[str, str, str]]:
    return {(f.rule, f.node, f.flow.label if f.flow else "") for f in report.findings}


class OracleTests(unittest.TestCase):
    def test_engine_agrees_with_the_second_implementation(self):
        total = 0
        for seed in range(N):
            arch, policy = random_case(seed)
            got, want = triples(evaluate(arch, policy)), oracle(arch, policy)
            self.assertEqual(got, want, f"seed {seed}")
            total += len(want)
        self.assertGreater(total, 1000)  # the cases are not trivially empty


class InvarianceTests(unittest.TestCase):
    def test_order_of_nodes_and_flows_changes_nothing(self):
        for seed in range(300):
            arch, policy = random_case(seed)
            rng = random.Random(seed)
            nodes, flows = list(arch.nodes.values()), list(arch.flows)
            rng.shuffle(nodes)
            rng.shuffle(flows)
            shuffled = Architecture.of(nodes, flows)
            a, b = evaluate(arch, policy), evaluate(shuffled, policy)
            self.assertEqual(a.findings, b.findings, f"seed {seed}")
            self.assertEqual(a.fingerprint, b.fingerprint)

    def test_serialization_round_trip_preserves_the_verdict(self):
        for seed in range(300):
            arch, policy = random_case(seed)
            arch2, policy2 = Architecture.from_dict(arch.to_dict()), Policy.from_dict(policy.to_dict())
            self.assertEqual(arch2, arch)
            self.assertEqual(policy2.to_dict(), policy.to_dict())
            self.assertEqual(evaluate(arch2, policy2).fingerprint, evaluate(arch, policy).fingerprint)
            self.assertEqual(evaluate(arch2, policy2).findings, evaluate(arch, policy).findings)

    def test_running_twice_gives_identical_output(self):
        arch, policy = random_case(7)
        self.assertEqual(evaluate(arch, policy).to_dict(), evaluate(arch, policy).to_dict())


class MonotonicityTests(unittest.TestCase):
    def test_narrowing_an_allowed_set_never_removes_an_error(self):
        checked = 0
        for seed in range(600):
            arch, policy = random_case(seed)
            before = len(evaluate(arch, policy).errors)
            for cls, allowed in list(policy.processing.items()):
                if len(allowed) > 1:
                    narrower = Policy(dict(policy.processing, **{cls: frozenset(sorted(allowed)[1:])}), policy.deny, policy.control,
                                      policy.transfer, policy.classes, home=policy.home)
                    self.assertGreaterEqual(len(evaluate(arch, narrower).errors), before, f"seed {seed} {cls}")
                    checked += 1
        self.assertGreater(checked, 200)

    def test_adding_a_deny_never_removes_an_error(self):
        for seed in range(400):
            arch, policy = random_case(seed)
            before = len(evaluate(arch, policy).errors)
            stricter = Policy(policy.processing, dict(policy.deny, personal=policy.deny.get("personal", frozenset()) | {"DE", "AE", "SA"}), policy.control, policy.transfer,
                              policy.classes, home=policy.home)
            self.assertGreaterEqual(len(evaluate(arch, stricter).errors), before, f"seed {seed}")

    def test_widening_to_everywhere_removes_every_processing_finding_on_known_locations(self):
        for seed in range(300):
            arch, policy = random_case(seed)
            wide = Policy({c: frozenset({"*"}) for c in policy.processing})
            for f in evaluate(arch, wide).findings:
                if f.rule == "processing":
                    self.assertIn("unknown location", f.reason)


class MutationTests(unittest.TestCase):
    def test_moving_any_node_out_of_bounds_is_always_caught(self):
        policy = Policy(processing={"personal": frozenset({"AE"})})
        caught = trials = 0
        for seed in range(400):
            rng = random.Random(seed)
            nodes = [Node(f"n{i}", rng.choice(["AE", "AE-DXB", "AE-AUH"])) for i in range(6)]
            flows = [Flow(f"n{rng.randrange(6)}", f"n{rng.randrange(6)}", "personal") for _ in range(8)]
            self.assertTrue(evaluate(Architecture.of(nodes, flows), policy).ok)
            moved = rng.randrange(6)
            nodes[moved] = Node(f"n{moved}", rng.choice(["US", "US-East", "DE", "SG", "unknown", "AEE"]))
            touching = [f for f in flows if f"n{moved}" in (f.src, f.dst)]
            if not touching:
                continue
            trials += 1
            report = evaluate(Architecture.of(nodes, flows), policy)
            flagged = {f.flow for f in report.findings if f.node == f"n{moved}"}
            caught += set(touching) <= flagged
        self.assertGreater(trials, 300)
        self.assertEqual(caught, trials)


class DiffAndLegacyTests(unittest.TestCase):
    def test_diff_is_empty_against_itself_and_symmetric(self):
        for seed in range(200):
            a, policy = random_case(seed)
            b, _ = random_case(seed + 10_000)
            self.assertEqual(diff(a, a, policy).new, ())
            forward, backward = diff(a, b, policy), diff(b, a, policy)
            self.assertEqual({f.key() for f in forward.new}, {f.key() for f in backward.resolved})
            self.assertEqual({f.key() for f in forward.resolved}, {f.key() for f in backward.new})

    def test_the_0_1_entry_point_matches_the_new_engine(self):
        for seed in range(200):
            arch, policy = random_case(seed)
            only = Policy(processing=policy.processing)
            legacy = check(arch.nodes, arch.flows, {c: set(v) for c, v in policy.processing.items()})
            self.assertEqual(sorted(legacy, key=lambda f: f.sort_key()), list(evaluate(arch, only).findings))


if __name__ == "__main__":
    unittest.main()
