import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sovereign_map import Architecture, Policy, evaluate
from sovereign_map.cli import main

ROOT = Path(__file__).resolve().parent.parent
ARCH = ROOT / "examples" / "gulf_rag" / "architecture.json"
POLICY = ROOT / "examples" / "gulf_rag" / "policy.json"


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class ReferenceArchitectureTests(unittest.TestCase):
    """The shipped example is pinned: these are the findings it is meant to demonstrate."""

    def test_findings_by_rule_and_node(self):
        report = evaluate(Architecture.load(ARCH), Policy.load(POLICY))
        got = sorted((f.rule, f.node, f.flow.dst if f.flow else "") for f in report.findings)
        self.assertEqual(got, [
            ("control", "embeddings-api", "embeddings-api"),
            ("control", "llm-gulf-region", "llm-gulf-region"),
            ("control", "log-saas", "log-saas"),
            ("deny", "embeddings-api", "embeddings-api"),
            ("processing", "embeddings-api", "embeddings-api"),
            ("processing", "log-saas", "log-saas"),
            ("processing", "log-saas", "log-saas"),
            ("protection", "", "embeddings-api"),
            ("transfer", "", "embeddings-api"),
        ])

    def test_the_compliant_parts_really_pass(self):
        report = evaluate(Architecture.load(ARCH), Policy.load(POLICY))
        flagged = {f.flow.label for f in report.findings if f.flow}
        for label in ["mobile-app -> api-gateway [customer-pii]", "api-gateway -> doc-store [customer-pii]", "api-gateway -> llm-local [customer-pii]",
                      "doc-store -> dr-site [financial-records]", "doc-store -> vector-db [financial-records]", "api-gateway -> log-saas [telemetry]"]:
            self.assertNotIn(label, flagged)


class CliTests(unittest.TestCase):
    def test_check_gate_and_formats(self):
        code, out, _ = run("check", str(ARCH), str(POLICY))
        self.assertEqual(code, 1)
        self.assertIn("FAIL", out)
        self.assertEqual(run("check", str(ARCH), str(POLICY), "--fail-on", "never")[0], 0)
        data = json.loads(run("check", str(ARCH), str(POLICY), "--format", "json")[1])
        self.assertEqual((data["ok"], data["summary"]["errors"]), (False, 9))
        self.assertEqual(json.loads(run("check", str(ARCH), str(POLICY), "--format", "sarif")[1])["version"], "2.1.0")
        self.assertIn("## Findings", run("check", str(ARCH), str(POLICY), "--format", "markdown")[1])

    def test_a_clean_architecture_passes_and_warnings_gate_only_on_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            arch, pol = Path(tmp, "a.json"), Path(tmp, "p.json")
            arch.write_text(json.dumps({"nodes": [{"name": "a", "jurisdiction": "AE"}, {"name": "b", "jurisdiction": "AE-DXB"}, {"name": "c", "jurisdiction": "AE"}],
                                        "flows": [{"src": "a", "dst": "b", "data_class": "personal"}]}))
            pol.write_text(json.dumps({"processing": {"personal": ["AE"]}}))
            self.assertEqual(run("check", str(arch), str(pol), "--lint")[0], 0)                  # c is an orphan: a warning
            self.assertEqual(run("check", str(arch), str(pol), "--lint", "--fail-on", "warning")[0], 1)
            self.assertEqual(run("check", str(arch), str(pol))[0], 0)

    def test_bad_input_is_exit_2(self):
        for argv in (["check", "/nonexistent.json", str(POLICY)], ["check", str(ARCH), "/nonexistent.json"]):
            code, _, err = run(*argv)
            self.assertEqual(code, 2)
            self.assertTrue(err.startswith("error:"))
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp, "bad.json")
            bad.write_text("{not json")
            self.assertEqual(run("check", str(bad), str(POLICY))[0], 2)
            bad.write_text(json.dumps({"nodes": [{"name": "a", "jurisdication": "AE"}]}))
            code, _, err = run("check", str(bad), str(POLICY))
            self.assertEqual(code, 2)
            self.assertIn("jurisdication", err)

    def test_diff_gate(self):
        arch = Architecture.load(ARCH)
        with tempfile.TemporaryDirectory() as tmp:
            worse = Path(tmp, "worse.json")
            d = arch.to_dict()
            d["flows"].append({"src": "doc-store", "dst": "embeddings-api", "data_class": "customer-pii"})
            worse.write_text(json.dumps(d))
            code, out, _ = run("diff", str(ARCH), str(worse), str(POLICY), "--fail-on-new")
            self.assertEqual(code, 1)
            self.assertIn("WORSE", out)
            self.assertEqual(run("diff", str(ARCH), str(worse), str(POLICY))[0], 0)
            self.assertEqual(run("diff", str(ARCH), str(ARCH), str(POLICY), "--fail-on-new")[0], 0)
            self.assertTrue(json.loads(run("diff", str(ARCH), str(worse), str(POLICY), "--json")[1])["worse"])

    def test_graph_exposure_egress_paths_fingerprint(self):
        self.assertTrue(run("graph", str(ARCH), str(POLICY))[1].startswith("flowchart LR"))
        self.assertIn("linkStyle", run("graph", str(ARCH), str(POLICY))[1])
        self.assertNotIn("linkStyle", run("graph", str(ARCH))[1])
        self.assertTrue(run("graph", str(ARCH), "--format", "dot")[1].startswith("digraph"))
        self.assertEqual(json.loads(run("exposure", str(ARCH))[1])["exposure"]["telemetry"], ["AE-DXB", "DE"])
        self.assertEqual(len(json.loads(run("egress", str(ARCH), "--home", "AE")[1])), 5)
        code, out, _ = run("paths", str(ARCH), "financial-records", "doc-store", "embeddings-api")
        self.assertEqual((code, json.loads(out)), (0, [["doc-store", "vector-db", "embeddings-api"]]))
        self.assertEqual(run("paths", str(ARCH), "financial-records", "embeddings-api", "doc-store")[0], 1)
        self.assertRegex(run("fingerprint", str(ARCH), str(POLICY))[1].strip(), r"^[0-9a-f]{64}$")

    def test_output_is_identical_across_hash_seeds_and_processes(self):
        outputs = set()
        for seed in ("1", "2", "999"):
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
            proc = subprocess.run([sys.executable, "-m", "sovereign_map", "check", str(ARCH), str(POLICY), "--format", "json", "--lint"],
                                  capture_output=True, text=True, env=env, cwd=ROOT)
            self.assertEqual(proc.returncode, 1, proc.stderr)
            outputs.add(proc.stdout)
        self.assertEqual(len(outputs), 1)

    def test_fingerprint_is_stable_across_processes(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        prints = {subprocess.run([sys.executable, "-m", "sovereign_map", "fingerprint", str(ARCH), str(POLICY)], capture_output=True, text=True,
                                 env=dict(env, PYTHONHASHSEED=s), cwd=ROOT).stdout for s in ("3", "4")}
        self.assertEqual(len(prints), 1)


if __name__ == "__main__":
    unittest.main()
