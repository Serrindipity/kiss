import argparse
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dc_checks import Runner
from lab_checks import collect, command, tag_result
from lab_catalog import CHECKS
from check_sysvol import scan


def args(path, **updates):
    values = dict(dc="192.0.2.10", domain="example.test", username="reader", listener=None,
                  nxc="nxc", timeout=2, plan=True, out=str(path), adcs=False, adcs_dc_only=False,
                  certipy="certipy")
    values.update(updates)
    return argparse.Namespace(**values)


class LabTests(unittest.TestCase):
    def test_all_checks_plan_without_network_and_unique_ids(self):
        with tempfile.TemporaryDirectory() as tmp, patch("dc_checks.subprocess.run") as external:
            r = Runner(args(Path(tmp) / "out", adcs=True))
            collect(r, CHECKS, True)
            external.assert_not_called()
            self.assertEqual(len(r.results), len(CHECKS) + 2)
            self.assertEqual(len({x["id"] for x in r.results}), len(r.results))
            self.assertTrue(all(x["status"] == "not_tested" for x in r.results))

    def test_listener_only_added_to_coercion_and_never_claims_callback(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = args(Path(tmp) / "out", listener="192.0.2.20")
            r = Runner(a)
            collect(r, [c for c in CHECKS if c.name in {"petitpotam", "zerologon"}], False)
            petit = next(x for x in r.results if x["id"] == "petitpotam")
            zero = next(x for x in r.results if x["id"] == "zerologon")
            self.assertIn("LISTENER=192.0.2.20", petit["command"])
            self.assertNotIn("LISTENER=192.0.2.20", zero["command"])
            self.assertIsNone(petit["callback_confirmed"])
            self.assertEqual(petit["assessment"], "receiver_evidence_required")

    def test_no_listener_is_interface_exposure_even_if_tool_says_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Runner(args(Path(tmp) / "out"))
            check = next(c for c in CHECKS if c.name == "petitpotam")
            (r.out / "tool.txt").write_text("VULNERABLE, PetitPotam\n")
            result = {"status": "completed", "stdout": "tool.txt"}
            r.results.append(result)
            tag_result(r, result, check)
            self.assertEqual(result["evidence_kind"], "rpc_interface_exposure")
            self.assertIsNone(result["callback_confirmed"])

    def test_auth_failure_stops_next_modules_even_if_process_successful(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Runner(args(Path(tmp) / "out", plan=False))
            r.secret = "/temporary/password"
            seen = []
            def fake_run(name, argv, *unused, **kwargs):
                seen.append(name)
                text = "zerologon nopac" if "modules" in name else ""
                if name == "zerologon":
                    text = "[-] STATUS_LOGON_FAILURE"
                path = name + ".txt"
                (r.out / path).write_text(text)
                result = {"id": name, "status": "completed", "stdout": path}
                r.results.append(result)
                return result
            with patch.object(r, "run", side_effect=fake_run):
                collect(r, [c for c in CHECKS if c.name in {"zerologon", "nopac"}], False)
            self.assertIn("zerologon", seen)
            self.assertNotIn("nopac", seen)
            self.assertEqual(sum(x == "zerologon" for x in seen), 1)

    def test_roast_paths_inside_evidence_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = args(Path(tmp) / "out")
            check = next(c for c in CHECKS if c.name == "kerberoast")
            self.assertEqual(command(check, a, "/tmp/pass")[-1], str(Path(a.out) / "kerberoast.txt"))

    def test_full_multiline_key_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = "-----BEGIN PRIVATE KEY-----\nSECRET-LINE-ONE\nSECRET-LINE-TWO\n-----END PRIVATE KEY-----\n"
            (Path(tmp) / "server.key").write_text(key)
            result = scan(Path(tmp), 10000, 10)["results"][0]
            self.assertEqual(result["content"], key)


if __name__ == "__main__":
    unittest.main()
