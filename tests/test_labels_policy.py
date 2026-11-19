import unittest

from sovereign_map import Architecture, Policy, TransferRule, covers
from sovereign_map.labels import is_unknown, root, same_jurisdiction


class CoverageTests(unittest.TestCase):
    def test_exact_and_case(self):
        self.assertTrue(covers("AE", "AE"))
        self.assertTrue(covers("ae", "AE"))
        self.assertFalse(covers("AE", "SA"))

    def test_sub_regions_sit_inside_their_jurisdiction(self):
        for label in ["US-East", "US/west", "US:gov"]:
            self.assertTrue(covers("US", label), label)
        self.assertFalse(covers("US", "USA"))          # a longer name is a different jurisdiction, not a sub-region
        self.assertFalse(covers("AE-DXB", "AE"))       # the other direction does not hold
        self.assertFalse(covers("US", "US-East", hierarchical=False))

    def test_builtin_groups(self):
        self.assertTrue(covers("EU", "DE"))
        self.assertTrue(covers("EU", "FR-IDF"))
        self.assertTrue(covers("EU", "EU"))            # a node labelled with the group itself still matches
        self.assertTrue(covers("EEA", "NO"))
        self.assertFalse(covers("EU", "NO"))
        self.assertTrue(covers("GCC", "AE-DXB"))
        self.assertFalse(covers("GCC", "EG"))
        self.assertTrue(covers("ASEAN", "ID"))
        self.assertEqual(len(__import__("sovereign_map").BUILTIN_GROUPS["EU"]), 27)

    def test_user_groups_override_and_nest(self):
        groups = {"EU": frozenset({"DE"}), "TRUSTED": frozenset({"EU", "AE"})}
        self.assertFalse(covers("EU", "FR", groups))   # overridden
        self.assertTrue(covers("TRUSTED", "DE", groups))
        self.assertTrue(covers("TRUSTED", "AE-DXB", groups))
        self.assertFalse(covers("TRUSTED", "FR", groups))

    def test_group_cycles_terminate(self):
        groups = {"A": frozenset({"B"}), "B": frozenset({"A"})}
        self.assertFalse(covers("A", "XX", groups))

    def test_unknown_locations_are_covered_by_nothing(self):
        for label in ["", "?", "unknown", "Unknown"]:
            self.assertTrue(is_unknown(label))
            self.assertFalse(covers("*", label), label)
            self.assertFalse(covers("AE", label), label)
        self.assertTrue(covers("*", "AE"))

    def test_root_and_same_jurisdiction(self):
        self.assertEqual(root("US-East"), "us")
        self.assertEqual(root("on-prem", hierarchical=False), "on-prem")
        self.assertTrue(same_jurisdiction("AE-DXB", "AE-AUH"))
        self.assertFalse(same_jurisdiction("AE-DXB", "SA-RUH"))
        self.assertFalse(same_jurisdiction("on-prem", "on-cloud", hierarchical=False))


class PolicyTests(unittest.TestCase):
    DATA = {
        "name": "p", "home": "AE", "classes": {"health": "personal"}, "open": ["public"],
        "processing": {"personal": ["AE", "EU"]}, "deny": {"health": ["US"]}, "control": {"personal": ["AE"]},
        "groups": {"TRUSTED": ["AE", "EU"]},
        "transfer": {"personal": {"mechanisms": ["SCC"], "free_within": ["GCC"], "protections": ["TLS"]}},
    }

    def test_round_trip(self):
        p = Policy.from_dict(self.DATA)
        self.assertEqual(Policy.from_dict(p.to_dict()).to_dict(), p.to_dict())
        self.assertEqual(p.transfer["personal"], TransferRule(frozenset({"scc"}), ("GCC",), frozenset({"tls"})))

    def test_canonical_output_ignores_input_order(self):
        a = Policy.from_dict({"processing": {"a": ["X", "Y"], "b": ["Z"]}})
        b = Policy.from_dict({"processing": {"b": ["Z"], "a": ["Y", "X"]}})
        self.assertEqual(a.to_dict(), b.to_dict())

    def test_lineage(self):
        p = Policy(classes={"a": "b", "b": "c"})
        self.assertEqual(p.lineage("a"), ["a", "b", "c"])
        self.assertEqual(p.lineage("zzz"), ["zzz"])

    def test_class_cycles_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "cycle"):
            Policy(classes={"a": "b", "b": "a"})
        with self.assertRaisesRegex(ValueError, "cycle"):
            Policy(classes={"a": "a"})

    def test_typos_in_keys_are_errors_not_silence(self):
        for bad in [{"procesing": {}}, {"transfer": {"x": {"mechanism": []}}}, {"processing": {"x": "AE"}}, {"hierarchical": "yes"}]:
            with self.assertRaises(ValueError, msg=str(bad)):
                Policy.from_dict(bad)

    def test_from_allowed(self):
        self.assertEqual(Policy.from_allowed({"personal": {"AE"}}).processing, {"personal": frozenset({"AE"})})


class ArchitectureTests(unittest.TestCase):
    DATA = {"nodes": [{"name": "a", "jurisdiction": "AE", "operator": "AE", "kind": "service", "tags": ["x", "y"]},
                      {"name": "b", "jurisdiction": "US"}],
            "flows": [{"src": "a", "dst": "b", "data_class": "personal", "mechanism": "scc", "protections": ["tls"], "note": "n"}]}

    def test_round_trip(self):
        arch = Architecture.from_dict(self.DATA)
        self.assertEqual(Architecture.from_dict(arch.to_dict()), arch)
        self.assertEqual(arch.to_dict(), self.DATA)

    def test_equality_ignores_order_and_duplicates(self):
        a = Architecture.from_dict({"nodes": [{"name": "a", "jurisdiction": "AE"}, {"name": "b", "jurisdiction": "US"}],
                                    "flows": [{"src": "a", "dst": "b", "data_class": "x"}, {"src": "a", "dst": "b", "data_class": "x"}]})
        b = Architecture.from_dict({"nodes": [{"name": "b", "jurisdiction": "US"}, {"name": "a", "jurisdiction": "AE"}],
                                    "flows": [{"src": "a", "dst": "b", "data_class": "x"}]})
        self.assertEqual(a, b)
        self.assertEqual(len(a.flows), 1)

    def test_bad_input_names_the_place(self):
        cases = [({"nodes": [{"name": "a"}]}, "nodes[0].jurisdiction"),
                 ({"nodes": [{"name": "a", "jurisdication": "AE"}]}, "jurisdication"),
                 ({"nodes": [{"name": "a", "jurisdiction": "AE"}, {"name": "a", "jurisdiction": "US"}]}, "declared twice"),
                 ({"flows": [{"src": "a", "dst": "b"}]}, "flows[0].data_class"),
                 ({"nodes": "x"}, "must be lists"),
                 ({"nodes": [{"name": "a", "jurisdiction": 5}]}, "expected a string")]
        for data, expected in cases:
            with self.assertRaisesRegex(ValueError, expected.replace("[", r"\[").replace("]", r"\]")):
                Architecture.from_dict(data)


if __name__ == "__main__":
    unittest.main()
