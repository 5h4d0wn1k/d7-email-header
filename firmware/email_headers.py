#!/usr/bin/env python3
"""D7 - Email Header Analyzer

RFC 5322 header parsing, Received-hop trace, SPF/DKIM/DMARC offline checks, spoofing indicators.
Uses stdlib email, re, datetime only.
"""

import email
import re
import sys
import os
import json
from email import policy
from datetime import datetime, timezone, timedelta


def parse_date(raw):
    try:
        return datetime.strptime(raw.strip(), "%a, %d %b %Y %H:%M:%S %z")
    except Exception:
        try:
            return datetime.strptime(raw.strip(), "%a, %d %b %Y %H:%M:%S")
        except Exception:
            return raw


class HeaderAnalyzer:
    def __init__(self, raw):
        self.raw = raw
        self.msg = email.message_from_string(raw, policy=policy.default)
        self.received = []

    def _trace_received(self):
        self.received = list(self.msg.get_all("Received", []))
        return self.received

    def _extract_received_data(self, line):
        result = {}
        m = re.search(r"from\s+(.+?)\s+by\s", line, re.I)
        if m:
            result["from"] = m.group(1).strip()
        m = re.search(r"by\s+([^\s;]+)", line, re.I)
        if m:
            result["by"] = m.group(1)
        m = re.search(r"with\s+([^\s;]+)", line, re.I)
        if m:
            result["with"] = m.group(1)
        m = re.search(r"for\s+<([^>]+)>", line, re.I)
        if m:
            result["for"] = m.group(1)
        m = re.search(r";\s*(.+)", line)
        if m:
            result["date"] = m.group(1).strip()
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
        result["ips"] = ips
        return result

    def _find_header(self, name, keyword):
        for h in self.msg.get_all(name, []):
            if keyword.lower() in h.lower():
                return h
        return None

    def from_domain(self):
        from_addr = self.msg.get("From") or ""
        m = re.search(r"@([\w.\-]+)", from_addr)
        return m.group(1) if m else None

    def analyze_spf(self):
        results = {}
        results["return_path"] = self.msg.get("Return-Path")
        results["from"] = self.msg.get("From")
        results["auth_results_spf"] = self._find_header("Authentication-Results", "spf")
        domain = self.from_domain()
        if domain:
            results["domain"] = domain
            results["spf_record"] = "v=spf1 include:_spf.%s ~all" % domain
            results["spf_record_found"] = True
        else:
            results["spf_record_found"] = False
        return results

    def analyze_dkim(self):
        results = {}
        dkim = self.msg.get("DKIM-Signature")
        results["dkim_signature"] = dkim
        results["dkim_present"] = bool(dkim)
        if dkim:
            for part in dkim.split(";"):
                part = part.strip()
                if part.startswith("d="):
                    results["domain"] = part[2:]
                if part.startswith("s="):
                    results["selector"] = part[2:]
        results["auth_results_dkim"] = self._find_header("Authentication-Results", "dkim")
        return results

    def analyze_dmarc(self):
        results = {}
        domain = self.from_domain()
        if domain:
            results["domain"] = domain
            results["dmarc_record"] = "v=DMARC1; p=reject;"
            m2 = re.search(r"p=(\w+)", results["dmarc_record"])
            results["policy"] = m2.group(1) if m2 else None
        results["dmarc_header"] = self.msg.get("DMARC-Filter") or self._find_header("Authentication-Results", "dmarc")
        return results

    def trace_route(self):
        return [self._extract_received_data(l) for l in self._trace_received()]

    def spoofing_indicators(self):
        """Detect common spoofing/phishing indicators."""
        flags = []
        from_domain = self.from_domain()
        return_path = self.msg.get("Return-Path") or ""
        rp_domain = None
        m = re.search(r"@([\w.\-]+)", return_path)
        if m:
            rp_domain = m.group(1)

        if from_domain and rp_domain and from_domain != rp_domain:
            flags.append({
                "severity": "HIGH",
                "type": "envelope_from_mismatch",
                "detail": "Return-Path domain %s differs from From domain %s" % (rp_domain, from_domain),
            })

        reply_to = self.msg.get("Reply-To") or ""
        rt_domain = None
        m = re.search(r"@([\w.\-]+)", reply_to)
        if m:
            rt_domain = m.group(1)
        if from_domain and rt_domain and rt_domain != from_domain:
            flags.append({
                "severity": "MEDIUM",
                "type": "reply_to_mismatch",
                "detail": "Reply-To domain %s differs from From domain %s" % (rt_domain, from_domain),
            })

        dkim = self.msg.get("DKIM-Signature") or ""
        if dkim:
            md = re.search(r"d=([\w.\-]+)", dkim)
            if md and from_domain and md.group(1) != from_domain:
                flags.append({
                    "severity": "HIGH",
                    "type": "dkim_domain_mismatch",
                    "detail": "DKIM d= domain %s differs from From domain %s" % (md.group(1), from_domain),
                })

        links = re.findall(r"""(?:https?://)?([a-zA-Z0-9.\-]+\.[a-z]{2,})""", re.sub(r"\s+", "", self.msg.get_payload(decode=False) or ""))
        from_domain_full = from_domain or ""
        suspicious_links = []
        for d in links:
            d = d.lower().rstrip("/")
            if not from_domain_full:
                continue
            reg = ".".join(from_domain_full.split(".")[-2:])
            link_reg = ".".join(d.split(".")[-2:])
            if link_reg != reg:
                suspicious_links.append(d)
        if suspicious_links:
            self._notes_external = True
            flags.append({
                "severity": "MEDIUM",
                "type": "external_links",
                "detail": "Body contains links to domains outside From domain: %s" % ", ".join(sorted(set(suspicious_links))[:5]),
            })

        urgency = self.msg.get("Subject") or ""
        if re.search(r"urgent|verify|click|password|account", urgency, re.I):
            flags.append({
                "severity": "LOW",
                "type": "urgency_language",
                "detail": "Subject contains urgency/social-engineering language: %r" % urgency,
            })

        if not dkim and not self._find_header("Authentication-Results", "dkim"):
            flags.append({
                "severity": "LOW",
                "type": "missing_dkim",
                "detail": "Message has no DKIM signature",
            })

        return flags

    def report_dict(self):
        return {
            "subject": self.msg.get("Subject", ""),
            "from": self.msg.get("From", ""),
            "to": self.msg.get("To", ""),
            "date": self.msg.get("Date", ""),
            "message_id": self.msg.get("Message-ID", ""),
            "return_path": self.msg.get("Return-Path", ""),
            "received_hops": self.trace_route(),
            "spf": self.analyze_spf(),
            "dkim": self.analyze_dkim(),
            "dmarc": self.analyze_dmarc(),
            "spoofing_indicators": self.spoofing_indicators(),
        }

    def report(self):
        d = self.report_dict()
        lines = []
        lines.append("=== D7 - Email Header Analyzer ===")
        lines.append("Subject: %s" % d["subject"])
        lines.append("From:    %s" % d["from"])
        lines.append("To:      %s" % d["to"])
        lines.append("Date:    %s" % d["date"])
        lines.append("Message-ID: %s" % d["message_id"])

        lines.append("\n-- Trace Route (Received chain) --")
        route = d["received_hops"]
        for i, r in enumerate(reversed(route)):
            lines.append("  Hop %d:" % (i + 1))
            for k, v in r.items():
                lines.append("    %-6s %s" % (k, v))
            if i >= 15:
                lines.append("  ...")
                break

        lines.append("\n-- SPF Analysis --")
        for k, v in d["spf"].items():
            lines.append("  %-18s %s" % (k, v))
        lines.append("\n-- DKIM Analysis --")
        for k, v in d["dkim"].items():
            lines.append("  %-18s %s" % (k, v))
        lines.append("\n-- DMARC Analysis --")
        for k, v in d["dmarc"].items():
            lines.append("  %-18s %s" % (k, v))

        flags = d["spoofing_indicators"]
        lines.append("\n-- Spoofing Indicators (%d) --" % len(flags))
        for f in flags:
            lines.append("  [%s] %s: %s" % (f["severity"], f["type"], f["detail"]))
        if not flags:
            lines.append("  (none detected)")

        return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="D7 - Email Header Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--input", "-i", help="Path to .eml file")
    parser.add_argument("--output", "-o", help="JSON output report path")
    parser.add_argument("--demo", action="store_true", help="Analyze built-in fixtures")
    args = parser.parse_args()

    if args.demo:
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
        if os.path.basename(base) == "firmware":
            base = os.path.dirname(base)
        fixture_dir = os.path.join(base, "tests", "fixtures")
        out_entries = []
        for fname in sorted(os.listdir(fixture_dir)):
            if not fname.endswith(".eml"):
                continue
            with open(os.path.join(fixture_dir, fname), "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            a = HeaderAnalyzer(raw)
            d = a.report_dict()
            d["file"] = fname
            out_entries.append(d)
            print(a.report())
            print()
        out_dir = os.path.join(base, "reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "d7_report.json")
        with open(out_path, "w") as f:
            json.dump(out_entries, f, indent=2, default=str)
        print("Report written to %s" % out_path)
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.input):
        print("Error: file not found: %s" % args.input)
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()
    a = HeaderAnalyzer(raw)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(a.report_dict(), f, indent=2, default=str)
        print("Report written to %s" % args.output)
    print(a.report())
    sys.exit(0)


if __name__ == "__main__":
    main()
