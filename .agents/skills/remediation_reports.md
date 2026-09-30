# Skill: remediation_reports

## Remediation
1. Data file `remediation/remediation.yaml`: rule_id, summary, steps, references. Steps for common servers (for example Postfix, Dovecot, Exim) are written per server, and the exact directive names and syntax are checked against the current documentation for the version before they go in, with the doc URL recorded.
2. The engine only maps rule_id to remediation. It does not generate advice freely.
3. Ordered by priority rank, and steps are copyable.

## Reports
Formats: JSON (the canonical model, same as the API), self-contained HTML (inline CSS, no external requests, works offline), PDF (ReportLab).
Every report contains: capture filename, SHA-256, size, packet count, time range, tool version, analysis timestamp; posture score with factor breakdown; findings with evidence frames, endpoints and Wireshark filter; remediation; drift section when present; a Methodology and Limitations section (passive analysis; TLS 1.3 certificates not observable; message-layer only where cleartext; anomalies are deviations, not attacks).

## Rules
- All captured strings (certificate subjects, SNI, banners, hostnames) are attacker-controlled. HTML-escape every one in the HTML report, and never build markup from them in the PDF.
- Reports never contain payloads or credentials.
- The same finding must show the same score contribution in JSON, HTML and PDF.
