# D7 — Email Header Analyzer

RFC 5322 email header parsing, Received-hop trace, offline SPF/DKIM/DMARC checks, and spoofing indicator detection.

## IMPORTANT: Read before use.

This tool is for **authorized educational and blue-team analysis only**. Analyze emails you are permitted to review (your own inbox, authorized incident-response mail). All fixtures/example data are synthetic with fictional addresses using `.example` domains and RFC 5737 documentation IPs.

## Features

- **Full RFC 5322 header parsing** via Python stdlib `email` module
- **Received-hop chain trace** (oldest first) with protocol, host, IP extraction
- **SPF analysis**: Return-Path / From domain correlation, Authentication-Results parsing
- **DKIM analysis**: signature extraction, d=/s= fields, domain verification
- **DMARC analysis**: policy extraction
- **Spoofing indicator detection**: envelope-from mismatch, Reply-To mismatch, DKIM domain mismatch, external links, urgency language, missing DKIM
- **JSON report output**

## Quick Start

```bash
# Analyze the built-in fixtures (legit + spoof demo)
python3 cli.py --demo

# Analyze a real .eml file
python3 cli.py --input email.eml --output reports/report.json
```

## Parsed Elements

- Headers: Subject, From, To, Date, Message-ID, Return-Path, Reply-To
- Received: from/by/with/for, date, embedded IPs
- Authentication-Results (SPF/DKIM/DMARC)
- DKIM-Signature (d=, s=, a=, c=)
- Body external links

## Testing

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `python3 cli.py --demo` — should exit 0, print two reports, flag the spoof fixture
2. Run `python3 -m unittest discover -s tests` — all tests pass
3. Verify `reports/d7_report.json` contains both emails with spoofing indicators

## Metrics

- Formats parsed: RFC 5322 email (`.eml`)
- Spoofing indicator types: 6 (envelope_from_mismatch, reply_to_mismatch, dkim_domain_mismatch, external_links, urgency_language, missing_dkim)
- Test count: 14
- Demo exit code: 0

## License

MIT License — see [LICENSE](LICENSE).
