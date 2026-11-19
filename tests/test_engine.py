import unittest

from sovereign_map import Architecture, Flow, Node, Policy, TransferRule, audit, check, evaluate, fingerprint

NODES = [
    Node("app", "AE-DXB", "AE", "service"), Node("db", "AE-AUH", "AE", "datastore"), Node("llm-us", "US-East", "US", "model"),
    Node("llm-ae", "AE-DXB", "AE", "model"), Node("llm-ae-us-owned", "AE-DXB", "US", "model"), Node("logs", "DE", "DE", "observability"),
    Node("mystery", "unknown", "", "observability"), Node("riyadh", "SA-RUH", "SA", "datastore"), Node("lonely", "AE", "AE"),
]


def arch(*flows: Flow) -> Architecture:
    return Architecture.of(NODES, flows)


def rules(report):
    return sorted((f.rule, f.node) for f in report.findings)


class ProcessingTests(unittest.TestCase):
    P = Policy(processing={"personal": frozenset({"AE", "EU"})})

    def test_regions_of_an_allowed_jurisdiction_pass(self):
        self.assertTrue(evaluate(arch(Flow("app", "db", "personal")), self.P).ok)

    def test_group_members_pass(self):
        self.assertTrue(evaluate(arch(Flow("app", "logs", "personal")), self.P).ok)  # DE is in the EU group

    def test_both_ends_are_checked_and_named(self):
        r = evaluate(arch(Flow("llm-us", "llm-us", "personal")), self.P)
        self.assertEqual(rules(r), [("processing", "llm-us")])  # one node, one finding, even when it is both ends
        r = evaluate(arch(Flow("llm-us", "app", "personal")), self.P)
        self.assertEqual(rules(r), [("processing", "llm-us")])

    def test_old_message_is_kept(self):
        v = check({n.name: n for n in NODES}, [Flow("app", "llm-us", "personal")], {"personal": {"AE"}})
        self.assertEqual(v[0].reason, "personal may not be processed in US-East (llm-us)")

    def test_unknown_location_is_always_a_finding_for_a_restricted_class(self):
        r = evaluate(arch(Flow("app", "mystery", "personal")), Policy(processing={"personal": frozenset({"*"})}))
        self.assertIn("an unknown location", r.findings[0].reason)

    def test_unknown_node(self):
        r = evaluate(arch(Flow("app", "ghost", "personal"), Flow("ghost", "ghost2", "x")), self.P)
        self.assertEqual([f.rule for f in r.findings], ["unknown-node", "unknown-node"])
        self.assertEqual(sorted(f.reason for f in r.findings), ["unknown node: ghost", "unknown node: ghost, ghost2"])

    def test_unrestricted_class_passes_anywhere(self):
        self.assertTrue(evaluate(arch(Flow("app", "llm-us", "public")), self.P).ok)

    def test_hint_names_compliant_nodes_of_the_same_kind(self):
        f = evaluate(arch(Flow("app", "llm-us", "personal")), self.P).findings[0]
        self.assertIn("permitted: AE, EU", f.hint)
        self.assertIn("llm-ae", f.hint)
        self.assertNotIn("logs", f.hint)

    def test_flat_labels_when_hierarchy_is_off(self):
        p = Policy(processing={"personal": frozenset({"AE"})}, hierarchical=False)
        self.assertFalse(evaluate(arch(Flow("app", "db", "personal")), p).ok)


class DenyControlTests(unittest.TestCase):
    def test_deny_beats_nothing_else(self):
        p = Policy(deny={"personal": frozenset({"US"})})
        r = evaluate(arch(Flow("app", "llm-us", "personal")), p)
        self.assertEqual(rules(r), [("deny", "llm-us")])

    def test_control_catches_a_foreign_operator_in_a_local_region(self):
        p = Policy(processing={"personal": frozenset({"AE"})}, control={"personal": frozenset({"AE"})})
        r = evaluate(arch(Flow("app", "llm-ae-us-owned", "personal")), p)
        self.assertEqual(rules(r), [("control", "llm-ae-us-owned")])  # location passes, control does not
        self.assertTrue(evaluate(arch(Flow("app", "llm-ae", "personal")), p).ok)

    def test_undeclared_operator_is_a_warning_not_a_guess(self):
        p = Policy(control={"personal": frozenset({"AE"})})
        r = evaluate(arch(Flow("app", "mystery", "personal")), p)
        self.assertEqual(rules(r), [("control-undeclared", "mystery")])
        self.assertTrue(r.ok)  # a warning does not fail the run
        self.assertEqual(len(r.warnings), 1)


class InheritanceTests(unittest.TestCase):
    P = Policy(processing={"personal": frozenset({"AE", "EU"}), "health": frozenset({"AE"})}, classes={"health": "personal"})

    def test_child_must_satisfy_its_own_and_its_parents_rules(self):
        r = evaluate(arch(Flow("app", "logs", "health")), self.P)  # DE is fine for personal, not for health
        self.assertEqual([f.rule for f in r.findings], ["processing"])
        self.assertNotIn("inherited", r.findings[0].reason)

    def test_parent_rules_apply_to_a_child_with_no_rule_of_its_own(self):
        p = Policy(processing={"personal": frozenset({"AE"})}, classes={"support-ticket": "personal"})
        r = evaluate(arch(Flow("app", "llm-us", "support-ticket")), p)
        self.assertIn("inherited from personal", r.findings[0].reason)

    def test_grandparents(self):
        p = Policy(processing={"a": frozenset({"AE"})}, classes={"c": "b", "b": "a"})
        self.assertFalse(evaluate(arch(Flow("app", "llm-us", "c")), p).ok)


class TransferTests(unittest.TestCase):
    P = Policy(transfer={"personal": TransferRule(frozenset({"scc", "adequacy"}), ("GCC",), frozenset({"tls", "customer-key"}))})

    def test_moves_between_regions_of_one_jurisdiction_need_nothing(self):
        self.assertTrue(evaluate(arch(Flow("app", "db", "personal")), self.P).ok)

    def test_free_within_a_group(self):
        self.assertTrue(evaluate(arch(Flow("app", "riyadh", "personal")), self.P).ok)  # AE to SA, both GCC

    def test_mechanism_required_outside_the_group(self):
        r = evaluate(arch(Flow("app", "llm-us", "personal", protections=("tls", "customer-key"))), self.P)
        self.assertEqual([f.rule for f in r.findings], ["transfer"])
        self.assertIn("'none'", r.findings[0].reason)

    def test_matching_ignores_case_and_accepts_any_listed_mechanism(self):
        f = Flow("app", "llm-us", "personal", mechanism="ADEQUACY", protections=("TLS", "Customer-Key"))
        self.assertTrue(evaluate(arch(f), self.P).ok)

    def test_missing_protection_is_named(self):
        r = evaluate(arch(Flow("app", "llm-us", "personal", mechanism="scc", protections=("tls",))), self.P)
        self.assertEqual([f.rule for f in r.findings], ["protection"])
        self.assertIn("customer-key", r.findings[0].reason)

    def test_an_empty_mechanism_list_means_none_is_needed(self):
        p = Policy(transfer={"personal": TransferRule()})
        self.assertTrue(evaluate(arch(Flow("app", "llm-us", "personal")), p).ok)


class ReportTests(unittest.TestCase):
    def test_summary_exposure_and_egress(self):
        p = Policy(processing={"personal": frozenset({"AE"})}, home="AE")
        r = evaluate(arch(Flow("app", "db", "personal"), Flow("app", "llm-us", "personal")), p)
        d = r.to_dict()
        self.assertEqual((d["ok"], d["summary"]["errors"], d["summary"]["flows"]), (False, 1, 2))
        self.assertEqual(d["exposure"], {"personal": ["AE-AUH", "AE-DXB", "US-East"]})
        self.assertEqual([f["dst"] for f in d["egress"]], ["llm-us"])  # app to db stays inside AE

    def test_findings_are_sorted_errors_first(self):
        p = Policy(processing={"personal": frozenset({"AE"})}, control={"personal": frozenset({"AE"})})
        r = evaluate(arch(Flow("app", "mystery", "personal"), Flow("app", "llm-us", "personal")), p)
        severities = [f.severity for f in r.findings]
        self.assertEqual(severities, sorted(severities))

    def test_fingerprint_ignores_order_and_changes_with_content(self):
        p = Policy(processing={"personal": frozenset({"AE"}), "x": frozenset({"AE"})})
        f1, f2 = Flow("app", "db", "personal"), Flow("app", "llm-us", "x")
        a1, a2 = Architecture.of(NODES, [f1, f2]), Architecture.of(list(reversed(NODES)), [f2, f1])
        self.assertEqual(fingerprint(a1, p.to_dict()), fingerprint(a2, p.to_dict()))
        p2 = Policy(processing={"personal": frozenset({"AE", "SA"}), "x": frozenset({"AE"})})
        self.assertNotEqual(fingerprint(a1, p.to_dict()), fingerprint(a1, p2.to_dict()))
        self.assertRegex(evaluate(a1, p).fingerprint, r"^[0-9a-f]{64}$")


class LintTests(unittest.TestCase):
    def test_lint_findings(self):
        p = Policy(processing={"personal": frozenset({"AE"}), "persnal": frozenset({"AE"})}, open=frozenset({"public"}))
        r = audit(arch(Flow("app", "db", "personal"), Flow("app", "db", "public"), Flow("app", "mystery", "usage")), p)
        got = {(f.rule, f.node or (f.flow.data_class if f.flow else "")) for f in r.warnings}
        self.assertIn(("orphan-node", "lonely"), got)
        self.assertIn(("unknown-location", "mystery"), got)
        self.assertIn(("unruled-class", "usage"), got)
        self.assertIn(("unused-rule", ""), got)   # "persnal" is a typo for "personal"
        self.assertNotIn(("unruled-class", "public"), got)
        self.assertNotIn(("unruled-class", "personal"), got)

    def test_lint_is_off_by_default_so_the_old_behaviour_is_unchanged(self):
        self.assertEqual(evaluate(arch(Flow("app", "db", "usage")), Policy()).findings, ())



class ReadmeTests(unittest.TestCase):
    def test_the_readme_example_gives_the_output_it_shows(self):
        a = Architecture.of(
            [Node("app", "AE-DXB", operator="AE"), Node("vectordb", "AE-AUH", operator="AE"),
             Node("llm-api", "US-East", operator="US", kind="model"), Node("llm-local", "AE-DXB", operator="AE", kind="model")],
            [Flow("app", "vectordb", "personal"), Flow("app", "llm-api", "personal")])
        p = Policy(processing={"personal": frozenset({"AE", "EU"})}, control={"personal": frozenset({"AE"})}, home="AE")
        r = evaluate(a, p)
        self.assertFalse(r.ok)
        self.assertEqual([(f.rule, f.reason, f.hint) for f in r.findings], [
            ("control", "personal is handled by llm-api, operated under US law", "operator must be under: AE"),
            ("processing", "personal may not be processed in US-East (llm-api)", "permitted: AE, EU; compliant model already in this architecture: llm-local"),
        ])


if __name__ == "__main__":
    unittest.main()
