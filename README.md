> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# D7 — Email Header Analyzer

**Email header and source analysis** by **5h4d0wn1k** for **phishing triage
and spoof detection**: RFC 5322 header parsing, Received-hop tracing, offline
SPF/DKIM/DMARC validation and six spoofing-indicator checks with JSON report
output. Python-only, deterministic on synthetic `.eml` fixtures.

## Why analyze email headers

Roughly 90% of breaches start with an email — and the fastest way to decide
"malicious or not" is the header, not the body. This tool parses a `.eml` and
lays out the Received-hop chain, cross-checks envelope (`Return-Path`) vs
`From`, pulls DKIM `d=`/`s=` fields, extracts DMARC policy and flags the
phishing tells: mismatched Reply-To, external links, urgency language and
missing signatures. Spoofing indicators surface as structured findings ready
for triage notes or a report. Use it only on mail you are permitted to review
(your own inbox or authorized incident-response artifacts) — all bundled
fixtures use `.example` domains and RFC 5737 documentation IPs. See
[ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **RFC 5322 parsing** — full header extraction via Python's stdlib `email`
  module (`Subject`, `From`, `To`, `Date`, `Message-ID`, `Return-Path`,
  `Reply-To`).
- **Received-hop chain trace** — oldest-first chain with `from/by/with/for`,
  timestamps and embedded IPs.
- **SPF analysis** — `Return-Path`/`From` domain correlation and
  `Authentication-Results` parsing (`analyze_spf`).
- **DKIM analysis** — signature extraction with `d=`/`s=`/`a=`/`c=` and
  domain verification (`analyze_dkim`).
- **DMARC analysis** — policy extraction from headers / records
  (`analyze_dmarc`).
- **Spoofing indicators** — `envelope_from_mismatch`, `reply_to_mismatch`,
  `dkim_domain_mismatch`, `external_links`, `urgency_language`,
  `missing_dkim` (`spoofing_indicators`).
- **JSON reports** — structured output for both bulk and single-file review.

## Quickstart

```bash
# Analyze the built-in fixtures (legit + spoof demo)
python3 cli.py --demo

# Analyze a real .eml file
python3 cli.py --input email.eml --output reports/report.json

# Run the test suite (16 deterministic offline tests)
python3 -m unittest discover -s tests
```

## CLI

```
python3 cli.py [-h] [-i INPUT] [-o OUTPUT] [--demo]
```

- `-i, --input` — path to an `.eml` file (RFC 5322 message).
- `-o, --output` — JSON report output path.
- `--demo` — analyze the bundled legit + spoof fixtures and print both
  reports (writes `reports/d7_report.json`, exit `0`).

## Project structure

```
cli.py                  # thin entry point into the engine
firmware/email_headers.py  # parser, analyzers, spoof indicators, CLI
tests/fixtures/         # synthetic legit_email.eml + spoof_email.eml
tests/                  # unittest coverage (16 tests)
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New SPF/DKIM/DMARC checks, indicator rules and `.eml` fixtures are welcome.
Open an issue or PR against the default branch; keep contributions scoped to
blue-team, educational tooling.

## License

MIT — see [LICENSE](LICENSE). Educational, blue-team software for analyzing
email you own or are explicitly permitted to review.