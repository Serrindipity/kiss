import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dc_checks import Runner, collect_ldap, host, ldap_command, parse_ldif, parse_nmap
from ldap_checks import CHECKS
from check_sysvol import indicators, scan


def arguments(out, **overrides):
    values = dict(out=str(out), dc="192.0.2.10", domain="example.test", ldap_host="dc.example.test",
                  base_dn=None, ldap_transport="ldaps", bind_user="reader@example.test", plan=False,
                  timeout=1, modules="ldap", guest=False, ms17_010=False)
    values.update(overrides)
    return argparse.Namespace(**values)


class ParsingTests(unittest.TestCase):
    def test_ldif_folding_base64_multivalues_and_binary(self):
        encoded = base64.b64encode("CN=Jöhn,DC=test".encode()).decode()
        entries = parse_ldif(f"dn:: {encoded}\nmember: CN=one,\n DC=test\nmember: CN=two,DC=test\nobjectSid:: AQIAAA==\n\n")
        self.assertEqual(entries[0]["dn"], ["CN=Jöhn,DC=test"])
        self.assertEqual(entries[0]["member"], ["CN=one,DC=test", "CN=two,DC=test"])
        self.assertEqual(entries[0]["objectsid"], [{"base64": "AQIAAA=="}])

    def test_ldif_urls_not_fetched_and_comments_not_entries(self):
        self.assertEqual(parse_ldif("# no matches\n"), [])
        self.assertEqual(parse_ldif("dn: cn=a\nphoto:< file:///etc/passwd\n")[0]["photo"],
                         [{"external_url_not_fetched": "file:///etc/passwd"}])

    def test_nmap_preserves_closed_ports_and_script_errors(self):
        xml = '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="445"><state state="closed"/></port></ports><hostscript><script id="smb2-security-mode" output="ERROR: failed"/></hostscript></host><runstats><finished exit="success"/></runstats></nmaprun>'
        data = parse_nmap(xml)
        self.assertEqual(data["hosts"][0]["ports"][0]["state"], "closed")
        self.assertEqual(data["hosts"][0]["scripts"][0]["output"], "ERROR: failed")

    def test_input_rejects_ranges_and_options(self):
        for value in ["-oX", "10.0.0.0/24", "http://dc", "dc;id", "dc name"]:
            with self.assertRaises(argparse.ArgumentTypeError):
                host(value)

    def test_starttls_mandatory_and_no_password_argument(self):
        args = arguments("unused", ldap_transport="ldap")
        cmd = ldap_command(args, "DC=test", "sub", "(objectClass=*)", ["cn"], True, "/tmp/password")
        self.assertIn("-ZZ", cmd)
        self.assertNotIn("-w", cmd)


class RunnerTests(unittest.TestCase):
    def test_plan_makes_no_subprocess_calls(self):
        with tempfile.TemporaryDirectory() as tmp, patch("dc_checks.subprocess.run") as run:
            r = Runner(arguments(Path(tmp) / "output", plan=True))
            collect_ldap(r)
            run.assert_not_called()
            self.assertEqual(len(r.results), len(CHECKS) + 3)
            self.assertTrue(all(row["status"] == "not_tested" for row in r.results))

    def test_failed_bind_stops_all_authenticated_queries(self):
        replies = [subprocess.CompletedProcess([], 0, "dn:\ndefaultNamingContext: DC=example,DC=test\n", ""),
                   subprocess.CompletedProcess([], 50, "", "Insufficient access"),
                   subprocess.CompletedProcess([], 49, "", "Invalid credentials")]
        with tempfile.TemporaryDirectory() as tmp, patch("dc_checks.shutil.which", return_value="tool"), \
                patch("dc_checks.subprocess.run", side_effect=replies) as run:
            r = Runner(arguments(Path(tmp) / "output"))
            r.secret = "/private/password"
            collect_ldap(r)
            self.assertEqual(run.call_count, 3)
            self.assertEqual(r.results[2]["status"], "authentication_failed")
            self.assertTrue(all(row["status"] == "not_tested" for row in r.results[3:]))
            saved = (r.out / "results.json").read_text()
            self.assertNotIn("/private/password", saved)
            self.assertIn("<temporary-password-file>", saved)

    def test_timeout_retains_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp, patch("dc_checks.shutil.which", return_value="tool"), \
                patch("dc_checks.subprocess.run", side_effect=subprocess.TimeoutExpired("tool", 1, b"partial")):
            r = Runner(arguments(Path(tmp) / "output"))
            result = r.run("test", ["tool"])
            self.assertEqual(result["status"], "timeout")
            self.assertEqual((r.out / result["stdout"]).read_text(), "partial")

    def test_partial_ldap_not_reported_complete(self):
        proc = subprocess.CompletedProcess([], 4, "dn: cn=a\ncn: a\n", "Size limit exceeded")
        with tempfile.TemporaryDirectory() as tmp, patch("dc_checks.shutil.which", return_value="tool"), \
                patch("dc_checks.subprocess.run", return_value=proc):
            r = Runner(arguments(Path(tmp) / "output"))
            result = r.run("query", ["ldapsearch"], parser=parse_ldif)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["returned_entries"], 1)

    def test_existing_evidence_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                Runner(arguments(tmp))


class ShareTests(unittest.TestCase):
    def test_indicators_preserve_secret_and_full_utf16_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Groups.xml").write_bytes('<User cpassword="NOT_A_REAL_SECRET"/>'.encode("utf-16"))
            report = scan(root, 10000, 10)
            self.assertEqual(report["results"][0]["indicators"][0]["indicator"], "gpp-cpassword")
            self.assertIn("NOT_A_REAL_SECRET", report["results"][0]["content"])
            self.assertIn("NOT_A_REAL_SECRET", report["results"][0]["indicators"][0]["evidence"])

    def test_symlink_size_and_file_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "big.txt").write_text("x" * 100)
            (root / "link.txt").symlink_to("/etc/passwd")
            report = scan(root, 10, 10)
            self.assertEqual({r.get("reason") for r in report["results"]}, {"size_limit", "symlink"})
            self.assertTrue(scan(root, 10, 1)["limited"])


if __name__ == "__main__":
    unittest.main()
