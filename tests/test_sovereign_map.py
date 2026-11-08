import unittest

from sovereign_map import Flow, Node, check, egress, exposure

NODES = {n.name: n for n in [
    Node("app", "AE"), Node("vectordb", "AE"), Node("llm-api", "US"), Node("backup", "EU"),
]}
RULES = {"personal": {"AE", "EU"}, "telemetry": {"AE", "EU", "US"}}


class SovereigntyTests(unittest.TestCase):
    def test_compliant_flows_pass(self):
        flows = [Flow("app", "vectordb", "personal"), Flow("app", "backup", "personal")]
        self.assertEqual(check(NODES, flows, RULES), [])

    def test_personal_data_to_us_is_flagged(self):
        violations = check(NODES, [Flow("app", "llm-api", "personal")], RULES)
        self.assertEqual(len(violations), 1)
        self.assertIn("US", violations[0].reason)

    def test_unrestricted_class_passes_anywhere(self):
        self.assertEqual(check(NODES, [Flow("app", "llm-api", "public")], RULES), [])

    def test_source_end_is_checked_too(self):
        flows = [Flow("llm-api", "app", "personal")]
        self.assertEqual(len(check(NODES, flows, RULES)), 1)

    def test_unknown_node_is_reported(self):
        violations = check(NODES, [Flow("app", "ghost", "personal")], RULES)
        self.assertIn("unknown node", violations[0].reason)

    def test_exposure_lists_jurisdictions_per_class(self):
        flows = [Flow("app", "llm-api", "telemetry"), Flow("app", "vectordb", "personal")]
        self.assertEqual(exposure(NODES, flows), {"personal": ["AE"], "telemetry": ["AE", "US"]})

    def test_egress(self):
        flows = [Flow("app", "vectordb", "personal"), Flow("app", "llm-api", "telemetry")]
        self.assertEqual([f.dst for f in egress(NODES, flows, "AE")], ["llm-api"])


if __name__ == "__main__":
    unittest.main()
