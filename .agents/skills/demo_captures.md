# Skill: demo_captures

## Purpose
Create controllable, synthetic ground truth so the tool can be tested and demonstrated. No real users' traffic.

## Lab
A Docker Compose lab with mail servers in variants: modern (TLS 1.2 and 1.3, ECDHE, valid chain); legacy (TLS 1.0 and 1.1 enabled, weak suites); expired certificate; self-signed certificate; hostname mismatch; STARTTLS not offered; plaintext AUTH allowed; implicit TLS on 465/993/995.
- Generate certificates with a small Python script using `cryptography` (arbitrary not_before and not_after), not the openssl CLI.
- Modern OpenSSL builds refuse SSLv3/TLS 1.0/1.1 by default. Use an older base image or lower the security level for the legacy server, and confirm a real handshake with the legacy version before capturing.
- Drive traffic with scripts: swaks for SMTP, `openssl s_client -starttls smtp|imap|pop3`, and a Python client. Capture with tcpdump.
- Plant PGP and S/MIME content in cleartext test messages for the message-layer checks.

## Capture set
- clean_baseline: at least 60 varied, healthy sessions.
- deviation: the baseline plus a few sessions from a client with unusual TLS parameters.
- legacy, expired, self_signed, no_starttls, cleartext_auth, tls13_only, mixed.
- drift_before and drift_after: the same server before and after a configuration change.

## Manifest
`demo_captures/manifest.json`: each capture with its expected findings (rule ids), expected score range, and expected drift changes. An automated test runs the analyzer on every capture and compares. The clean capture must produce no critical or high findings. Report precision and recall over the set.

## Rules
- Synthetic credentials and content only.
- Public sample captures (for example from the Wireshark sample captures wiki) are fine for parser smoke tests but have no controllable ground truth.
- Commit the small captures, or the scripts that regenerate them, so a fresh checkout can reproduce the demo.
