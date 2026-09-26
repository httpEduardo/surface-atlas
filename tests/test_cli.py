import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from surface_atlas.cli import EXIT_ERROR, EXIT_OK, EXIT_RISK, main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    return main(list(args), out=out, err=err), out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_text_report(self):
        code, out, _ = run("-i", str(EXAMPLES / "assets.json"), "-n", "2")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Top 2 of 5 assets", out)
        self.assertIn("owner coverage:       80%", out)

    def test_fail_on(self):
        code, _, _ = run("-i", str(EXAMPLES / "assets.json"), "--fail-on", "critical")
        self.assertEqual(code, EXIT_RISK)

    def test_json_report(self):
        _, out, _ = run("-i", str(EXAMPLES / "assets.json"), "-f", "json")
        data = json.loads(out)
        self.assertEqual(data["summary"]["assets"], 5)
        scores = [a["score"] for a in data["assets"]]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_csv_report(self):
        _, out, _ = run("-i", str(EXAMPLES / "assets.json"), "-f", "csv")
        self.assertTrue(out.startswith("id,host,env,owner,public,score,level,reasons"))
        self.assertEqual(len(out.strip().splitlines()), 6)

    def test_weights_file(self):
        code, out, _ = run("-i", str(EXAMPLES / "assets.json"), "-w", str(EXAMPLES / "weights.json"), "-f", "json")
        self.assertEqual(code, EXIT_OK)
        portal = next(a for a in json.loads(out)["assets"] if a["id"] == "web-portal")
        self.assertEqual(portal["score"], 30)

    def test_bad_inventory(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write('{"assets": {"not": "a list"}}')
        try:
            code, _, err = run("-i", fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)


if __name__ == "__main__":
    unittest.main()
