#!/usr/bin/env python3
"""Tests for D7 Email Header Analyzer."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from email_headers import HeaderAnalyzer

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def read_fixture(name):
    with open(os.path.join(FIXTURE_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


class TestLegitEmail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = HeaderAnalyzer(read_fixture("legit_email.eml"))

    def test_from(self):
        self.assertIn("Alice Example", self.a.msg.get("From"))

    def test_subject(self):
        self.assertEqual(self.a.msg.get("Subject"), "Quarterly security report")

    def test_received_hops(self):
        route = self.a.trace_route()
        self.assertGreaterEqual(len(route), 3)

    def test_received_ips_property(self):
        route = self.a.trace_route()
        ip_found = False
        for r in route:
            if r.get("ips"):
                ip_found = True
        self.assertTrue(ip_found)

    def test_spf_present(self):
        spf = self.a.analyze_spf()
        self.assertTrue(spf["spf_record_found"])

    def test_dkim_present(self):
        dkim = self.a.analyze_dkim()
        self.assertTrue(dkim["dkim_present"])
        self.assertEqual(dkim.get("domain"), "example.com")

    def test_dmarc_policy(self):
        dmarc = self.a.analyze_dmarc()
        self.assertEqual(dmarc.get("policy"), "reject")

    def test_no_high_severity_flags(self):
        flags = self.a.spoofing_indicators()
        high = [f for f in flags if f["severity"] == "HIGH"]
        self.assertEqual(len(high), 0)


class TestSpoofEmail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = HeaderAnalyzer(read_fixture("spoof_email.eml"))

    def test_envelope_from_mismatch(self):
        flags = self.a.spoofing_indicators()
        types = [f["type"] for f in flags]
        self.assertIn("envelope_from_mismatch", types)

    def test_reply_to_mismatch(self):
        flags = self.a.spoofing_indicators()
        types = [f["type"] for f in flags]
        self.assertIn("reply_to_mismatch", types)

    def test_dkim_domain_mismatch(self):
        flags = self.a.spoofing_indicators()
        types = [f["type"] for f in flags]
        self.assertIn("dkim_domain_mismatch", types)

    def test_received_hops(self):
        route = self.a.trace_route()
        self.assertGreaterEqual(len(route), 2)

    def test_external_link_detected(self):
        flags = self.a.spoofing_indicators()
        types = [f["type"] for f in flags]
        self.assertIn("external_links", types)


class TestCLIHelp(unittest.TestCase):
    def test_help_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)


class TestCLIDemo(unittest.TestCase):
    def test_demo_exits_zero(self):
        import subprocess
        cli = os.path.join(os.path.dirname(__file__), "..", "cli.py")
        r = subprocess.run([sys.executable, cli, "--demo"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Spoofing Indicators", r.stdout)


class TestParseDate(unittest.TestCase):
    def test_date_parses(self):
        from email_headers import parse_date
        d = parse_date("Tue, 15 Jan 2024 09:30:00 +0000")
        self.assertIsNotNone(d)
        self.assertEqual(d.year, 2024)


if __name__ == "__main__":
    unittest.main()
