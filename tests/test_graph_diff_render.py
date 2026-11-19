import json
import unittest

from sovereign_map import (
    Architecture,
    Flow,
    Node,
    Policy,
    cross_border,
    diff,
    egress,
    evaluate,
    exposure,
    holders,
    orphans,
    paths,
    reach,
    sinks,
    to_dot,
    to_markdown,
    to_mermaid,
    to_sarif,
    to_text,
)

ARCH = Architecture.of(
    [Node("app", "AE-DXB", "AE"), Node("db", "AE-AUH", "AE"), Node("llm", "US-East", "US", "model"), Node("logs", "DE", "DE"), Node("idle", "AE")],
    [Flow("app", "db", "personal"), Flow("app", "llm", "personal"), Flow("llm", "logs", "personal"), Flow("app", "logs", "telemetry"),
     Flow("db", "llm", "personal")],
)
POLICY = Policy(processing={"personal": frozenset({"AE"})}, home="AE")


class GraphTests(unittest.TestCase):
    def test_exposure(self):
        self.assertEqual(exposure(ARCH), {"personal": ["AE-AUH", "AE-DXB", "DE", "US-East"], "telemetry": ["AE-DXB", "DE"]})

    def test_exposure_and_egress_accept_the_old_call_shape(self):
        self.assertEqual(exposure(ARCH.nodes, ARCH.flows), exposure(ARCH))
        self.assertEqual(len(egress(ARCH.nodes, ARCH.flows, "AE")), 3)

    def test_egress_treats_regions_as_home_and_groups_as_home(self):
        self.assertEqual(sorted(f.label for f in egress(ARCH, None, "AE")),
                         ["app -> llm [personal]", "app -> logs [telemetry]", "db -> llm [personal]"])
        self.assertEqual(len(egress(ARCH, None, "GCC")), 3)
        self.assertEqual(sorted(f.dst for f in egress(ARCH, None, "ae-dxb")), ["db", "llm", "logs"])  # AE-AUH is outside the DXB region

    def test_unknown_destination_counts_as_leaving(self):
        a = Architecture.of([Node("x", "AE"), Node("y", "unknown")], [Flow("x", "y", "c")])
        self.assertEqual(len(egress(a, None, "AE")), 1)

    def test_cross_border_ignores_moves_inside_one_jurisdiction(self):
        m = cross_border(ARCH)
        self.assertNotIn(("AE-DXB", "AE-AUH"), m)
        self.assertEqual(m[("AE-DXB", "US-East")], ["personal"])
        self.assertEqual(m[("US-East", "DE")], ["personal"])

    def test_holders_reach_paths_sinks_orphans(self):
        self.assertEqual(holders(ARCH)["llm"], {"receives": ["personal"], "sends": ["personal"]})
        self.assertEqual(reach(ARCH, "app", "personal"), ["db", "llm", "logs"])
        self.assertEqual(reach(ARCH, "logs"), [])
        self.assertEqual(paths(ARCH, "personal", "app", "logs"), [["app", "llm", "logs"], ["app", "db", "llm", "logs"]])
        self.assertEqual(paths(ARCH, "telemetry", "app", "logs"), [["app", "logs"]])
        self.assertEqual(paths(ARCH, "personal", "logs", "app"), [])
        self.assertEqual(sinks(ARCH), ["logs"])
        self.assertEqual(orphans(ARCH), ["idle"])

    def test_paths_terminate_on_cycles_and_respect_the_limit(self):
        cyc = Architecture.of([Node(c, "AE") for c in "abc"], [Flow("a", "b", "x"), Flow("b", "a", "x"), Flow("b", "c", "x"), Flow("c", "a", "x")])
        self.assertEqual(paths(cyc, "x", "a", "c"), [["a", "b", "c"]])
        self.assertEqual(len(paths(cyc, "x", "a", "a")), 2)   # a cycle back to the start is found
        self.assertEqual(len(paths(cyc, "x", "a", "a", limit=1)), 1)


class DiffTests(unittest.TestCase):
    def test_adding_a_bad_flow_is_worse(self):
        after = Architecture.of(ARCH.nodes.values(), [*ARCH.flows, Flow("logs", "idle", "personal")])
        d = diff(ARCH, after, POLICY)
        self.assertTrue(d.worse)
        self.assertEqual([(f.rule, f.node) for f in d.new], [("processing", "logs")])
        self.assertEqual(d.flows_added, (Flow("logs", "idle", "personal"),))

    def test_fixing_is_not_worse_and_lists_what_was_resolved(self):
        bad = ARCH
        fixed = Architecture.of([*(n for n in ARCH.nodes.values() if n.name != "llm"), Node("llm", "AE-DXB", "AE", "model")], ARCH.flows)
        d = diff(bad, fixed, POLICY)
        self.assertFalse(d.worse)
        self.assertTrue(d.resolved)
        self.assertEqual(d.exposure_removed["personal"], ["US-East"])

    def test_identical_architectures_have_an_empty_diff(self):
        d = diff(ARCH, ARCH, POLICY)
        self.assertEqual((d.new, d.resolved, d.exposure_added, d.flows_added, d.egress_added), ((), (), {}, (), ()))

    def test_new_exposure_and_egress_and_nodes(self):
        after = Architecture.of([*ARCH.nodes.values(), Node("sg", "SG")], [*ARCH.flows, Flow("db", "sg", "telemetry")])
        d = diff(ARCH, after, Policy(home="AE"))
        self.assertEqual(d.exposure_added, {"telemetry": ["AE-AUH", "SG"]})
        self.assertEqual([f.dst for f in d.egress_added], ["sg"])
        self.assertEqual(d.nodes_added, ("sg",))
        self.assertFalse(d.worse)  # new exposure is reported, but only errors make a change worse
        json.dumps(d.to_dict())


class RenderTests(unittest.TestCase):
    REPORT = evaluate(ARCH, POLICY)

    def test_text(self):
        t = to_text(self.REPORT)
        self.assertIn("FAIL", t)
        self.assertIn(self.REPORT.fingerprint[:16], t)
        self.assertIn("fix: permitted: AE", t)

    def test_markdown_escapes_pipes_and_has_every_section(self):
        m = to_markdown(self.REPORT, ARCH)
        for part in ["# Data residency report", "## Findings", "## Exposure", "## Cross-border", "## Egress from AE", "not legal advice"]:
            self.assertIn(part, m)
        bad = evaluate(Architecture.of([Node("a", "AE"), Node("b", "US")], [Flow("a", "b", "x")]),
                       Policy(processing={"x": frozenset({"AE"})}))
        self.assertNotIn("||", to_markdown(bad))

    def test_dot(self):
        d = to_dot(ARCH, self.REPORT)
        self.assertEqual(d.count("subgraph cluster_"), 5)           # AE-AUH, AE-DXB, DE, US-East, and AE for the idle node
        self.assertEqual(d.count("->"), 5)
        self.assertEqual(d.count('style="dashed"'), 3)                  # app->llm, db->llm and llm->logs touch a node outside AE
        self.assertTrue(d.startswith("digraph") and d.rstrip().endswith("}"))

    def test_dot_quotes_awkward_names(self):
        a = Architecture.of([Node('we"ird', "AE"), Node("b", "AE")], [Flow('we"ird', "b", "c")])
        self.assertIn('"we\\"ird" -> "b"', to_dot(a))

    def test_mermaid(self):
        m = to_mermaid(ARCH, self.REPORT)
        self.assertTrue(m.startswith("flowchart LR"))
        self.assertEqual(m.count("-->"), 5)
        self.assertIn("linkStyle", m)
        self.assertEqual(m.count("subgraph "), m.count("\n  end"))
        self.assertNotIn("linkStyle", to_mermaid(ARCH))

    def test_sarif(self):
        s = to_sarif(self.REPORT, "arch.json")
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertEqual(len(run["results"]), len(self.REPORT.findings))
        self.assertEqual({r["id"] for r in run["tool"]["driver"]["rules"]}, {f.rule for f in self.REPORT.findings})
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["properties"]["fingerprint"], self.REPORT.fingerprint)
        json.dumps(s)


if __name__ == "__main__":
    unittest.main()
