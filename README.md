# D7 — Email Header Analyzer

Parses and analyzes email headers for SPF, DKIM, DMARC, and routing.

## Overview

This project analyzes email headers to:
- Parse the full header block
- Trace the Received chain (server routing)
- Evaluate SPF sender policy framework
- Evaluate DKIM signatures
- Evaluate DMARC policy alignment
- Extract IPs, hostnames, and timestamps

## Features

- **Header parsing**: email parser with full RFC policy
- **Trace route**: reconstructs the server hop chain
- **SPF**: check Return-Path, domain, authentication results
- **DKIM**: parse signature fields (d=, s=)
- **DMARC**: policy and record inspection
- **Built-in sample**: works without an input file

## Usage

```bash
python3 email_headers.py            # uses built-in sample
python3 email_headers.py email.eml  # analyze a saved .eml file
```

## Example Output

```
=== D7 - Email Header Analyzer ===
Subject: Test email header analysis
From:    Alice <alice@example.com>
...
-- Trace Route --
  Hop 1: from smtp.example.com  by mx1.example.net  with ESMTPS
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
