"""Tests for scripts/validate.py. Leak samples are built at runtime so this file stays clean."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import validate  # noqa: E402

TS_IP = ".".join(["100", "101", "2", "3"])
TS_NAME = "box." + "tail" + "abcd12" + "." + "ts" + ".net"


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        shutil.copytree(ROOT / "schema", self.tmp / "schema")
        shutil.copytree(ROOT / "hosts", self.tmp / "hosts")
        self.host = self.tmp / "hosts" / "example-host"

    def problems(self, denylist=()):
        return validate.validate(self.tmp, denylist)[1]

    def test_template_is_clean(self):
        self.assertEqual(validate.validate(ROOT)[1], [])

    def test_example_copy_is_clean(self):
        self.assertEqual(self.problems(), [])

    def test_tailnet_ip_value_fails(self):
        (self.host / "dash.toml").write_text(f'[paths]\nartifacts_dir = "/x"\n# {TS_IP}\n')
        self.assertTrue(any("tailnet IPv4" in p for p in self.problems()))

    def test_documentation_fixture_range_passes(self):
        (self.host / "dash.toml").write_text("# example peer 100.64.0.1\n")
        self.assertEqual(self.problems(), [])

    def test_ts_net_name_fails(self):
        (self.tmp / "NOTES.md").write_text(f"ssh {TS_NAME}\n")
        kinds = " ".join(self.problems())
        self.assertIn("tailnet DNS name", kinds)
        self.assertIn("tailnet id", kinds)

    def test_address_key_fails_even_inside_open_maps(self):
        (self.host / "files.toml").write_text("[services.dash]\nbridge_ip = 1\n")
        self.assertTrue(any("address-shaped key" in p for p in self.problems()))

    def test_unknown_key_and_component_fail(self):
        (self.host / "dash.toml").write_text('[voice]\nbroker_host = "x"\n')
        (self.host / "secrets.toml").write_text("")
        problems = self.problems()
        self.assertTrue(any("unknown key 'broker_host'" in p for p in problems))
        self.assertTrue(any("unknown component 'secrets'" in p for p in problems))

    def test_fqdn_cannot_be_a_hostname(self):
        (self.host / "devices.toml").write_text('[p]\nkind = "phone"\npeer_hostname = "p.example.com"\n')
        self.assertTrue(any("peer_hostname" in p for p in self.problems()))

    def test_secret_fails_without_echoing_it(self):
        token = "gh" + "p_" + "A" * 36
        (self.tmp / "x.txt").write_text(token)
        problems = self.problems()
        self.assertTrue(any("GitHub token" in p for p in problems))
        self.assertFalse(any(token in p for p in problems))

    def test_denylist_literal_fails_without_echoing_it(self):
        (self.tmp / "x.txt").write_text("mounted at /very/private/root\n")
        problems = self.problems(["/very/private/root"])
        self.assertEqual(len(problems), 1)
        self.assertNotIn("/very/private/root", problems[0])

    def test_port_range(self):
        (self.host / "dash.toml").write_text("[voice]\nbroker_port = 70000\n")
        self.assertTrue(any("above 65535" in p for p in self.problems()))


if __name__ == "__main__":
    unittest.main()
