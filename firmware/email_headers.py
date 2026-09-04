#!/usr/bin/env python3
"""D7 - Email Header Analyzer

Email header parsing, SPF/DKIM/DMARC analysis, trace route.
Uses email, re, datetime only (email.policy).
"""

import email
import re
import sys
import os
from email import policy
from datetime import datetime

SPF_LOOKUP = (
    "v=spf1 include:_spf.example.com ~all",
)
DKIM_SELECTOR = "default"
DMARC_POLICY = "v=DMARC1; p=reject;"


def parse_date(raw):
    try:
        return datetime.strptime(raw.strip(), "%a, %d %b %Y %H:%M:%S %z")
    except Exception:
        return raw


class HeaderAnalyzer:
    def __init__(self, raw):
        self.raw = raw
        self.msg = email.message_from_string(raw, policy=policy.default)
        self.received = []

    def _trace_received(self):
        """Parse all Received headers (oldest first)."""
        self.received = list(self.msg.get_all("Received", []))
        return self.received

    def _extract_received_data(self, received_line):
        result = {}
        # from
        m = re.search(r"from\s+(.+?)\s+by\s", received_line, re.I)
        if m:
            result["from"] = m.group(1).strip()
        m = re.search(r"by\s+([^\s;]+)", received_line, re.I)
        if m:
            result["by"] = m.group(1)
        m = re.search(r"with\s+([^\s;]+)", received_line, re.I)
        if m:
            result["with"] = m.group(1)
        m = re.search(r"id\s+([^\s;]+)", received_line, re.I)
        if m:
            result["id"] = m.group(1)
        m = re.search(r"for\s+<([^>]+)>", received_line, re.I)
        if m:
            result["for"] = m.group(1)
        m = re.search(r";\s*(.+)", received_line)
        if m:
            result["date"] = m.group(1).strip()
        # IP addresses
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", received_line)
        result["ips"] = ips
        return result

    def analyze_spf(self):
        """Analyze SPF presence and Return-Path."""
        results = {}
        results["return_path"] = self.msg.get("Return-Path")
        results["from"] = self.msg.get("From")
        spf_header = self._find_header("Authentication-Results", "spf")
        results["auth_results_spf"] = spf_header
        dns = SPF_LOOKUP[0]
        # crude evaluation: check that domain in From has SPF
        from_addr = self.msg.get("From") or ""
        m = re.search(r"@([\w.\-]+)", from_addr)
        if m:
            domain = m.group(1)
            results["domain"] = domain
            if "~all" in dns or "-all" in dns or "~all" in dns:
                results["spf_record_found"] = True
                results["spf_record"] = dns
            else:
                results["spf_record_found"] = False
        return results

    def analyze_dkim(self):
        results = {}
        dkim = self.msg.get("DKIM-Signature")
        results["dkim_signature"] = dkim
        if dkim:
            results["dkim_present"] = True
            for part in dkim.split(";"):
                part = part.strip()
                if part.startswith("d="):
                    results["domain"] = part[2:]
                if part.startswith("s="):
                    results["selector"] = part[2:]
        else:
            results["dkim_present"] = False
        auth = self._find_header("Authentication-Results", "dkim")
        results["auth_results_dkim"] = auth
        return results

    def analyze_dmarc(self):
        results = {}
        dmarc = self.msg.get("DMARC-Filter")
        results["dmarc_header"] = dmarc
        # In real analysis you'd query _dmarc.<domain> TXT record
        from_addr = self.msg.get("From") or ""
        m = re.search(r"@([\w.\-]+)", from_addr)
        if m:
            domain = m.group(1)
            results["domain"] = domain
            # simulate record
            results["dmarc_record"] = DMARC_POLICY
            m2 = re.search(r"p=(\w+)", DMARC_POLICY)
            results["policy"] = m2.group(1) if m2 else None
        return results

    def _find_header(self, name, keyword):
        for h in self.msg.get_all(name, []):
            if keyword.lower() in h.lower():
                return h
        return None

    def trace_route(self):
        data = []
        for line in self._trace_received():
            data.append(self._extract_received_data(line))
        return data

    def report(self):
        lines = []
        lines.append("=== D7 - Email Header Analyzer ===")
        lines.append("Subject: %s" % self.msg.get("Subject", ""))
        lines.append("From:    %s" % self.msg.get("From", ""))
        lines.append("To:      %s" % self.msg.get("To", ""))
        lines.append("Date:    %s" % self.msg.get("Date", ""))
        lines.append("Message-ID: %s" % self.msg.get("Message-ID", ""))

        lines.append("\n-- Trace Route (Received chain, oldest first) --")
        route = self.trace_route()
        for i, r in enumerate(reversed(route)):
            lines.append("  Hop %d:" % (i + 1))
            for k, v in r.items():
                lines.append("    %-6s %s" % (k, v))
            if i >= 15:
                lines.append("  ...")
                break

        lines.append("\n-- SPF Analysis --")
        spf = self.analyze_spf()
        for k, v in spf.items():
            lines.append("  %-18s %s" % (k, v))

        lines.append("\n-- DKIM Analysis --")
        dkim = self.analyze_dkim()
        for k, v in dkim.items():
            lines.append("  %-18s %s" % (k, v))

        lines.append("\n-- DMARC Analysis --")
        dmarc = self.analyze_dmarc()
        for k, v in dmarc.items():
            lines.append("  %-18s %s" % (k, v))

        return "\n".join(lines)


SAMPLE = """Return-Path: <alice@example.com>
Received: from mx1.example.net (mx1.example.net [192.0.2.10])
\tby mail.local (Postfix) with ESMTP id ABC123
\tfor <bob@local.test>; Tue, 15 Jan 2024 09:30:12 +0000 (UTC)
Received: from smtp.example.com (smtp.example.com [198.51.100.7])
\tby mx1.example.net (Postfix) with ESMTPS id XYZ789
\tfor <bob@local.test>; Tue, 15 Jan 2024 09:30:11 +0000 (UTC)
From: Alice <alice@example.com>
To: bob@local.test
Subject: Test email header analysis
Date: Tue, 15 Jan 2024 09:30:00 +0000
Message-ID: <20240115093000@example.com>
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default; c=relaxed/relaxed;
Authentication-Results: mx1.example.net; spf=pass smtp.example.com; dkim=pass


Hello Bob, this is a test.
"""


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
        else:
            raw = path
    else:
        raw = SAMPLE
        print("No input file; using built-in sample email.\n")
    try:
        a = HeaderAnalyzer(raw)
        print(a.report())
        return 0
    except Exception as e:
        print("Error: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
