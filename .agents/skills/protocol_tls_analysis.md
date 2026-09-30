# Skill: protocol_tls_analysis

## Purpose
Identify email protocols, detect STARTTLS behaviour, dissect TLS handshakes, extract and validate certificates, and flag weak cryptography.

## Protocol identification
Use port and payload evidence together: SMTP banner `220 ... ESMTP` and EHLO, IMAP `* OK` greeting and CAPABILITY, POP3 `+OK` greeting and CAPA. Standard ports: SMTP 25/587/465, IMAP 143/993, POP3 110/995. Non-standard ports are identified by banner and reported with lower confidence. Unrecognized traffic is `unknown`, not guessed.

## Transport classification per session
- implicit_tls: ClientHello is the first client bytes (465, 993, 995).
- starttls: plaintext greeting, then the upgrade command (SMTP `STARTTLS` then `220`; IMAP `STARTTLS` then tagged `OK`; POP3 `STLS` then `+OK`), then a ClientHello on the same TCP stream.
- plaintext: no TLS at all.
Record advertised, initiated, succeeded. Findings: STARTTLS advertised but the session continued in plaintext; authentication attempted before the upgrade; an upgrade command answered with an error followed by plaintext. Suspected STARTTLS stripping (a server that advertises STARTTLS in one session but not in another) is a low-confidence finding and says so.

## TLS fields
- Version: for TLS 1.3 the ServerHello legacy version field says 1.2. Read the supported_versions extension first and use the record/legacy version only when it is absent.
- Cipher suite: map the IANA code to its name. For TLS 1.2 derive key exchange, authentication, cipher and MAC from the name. TLS 1.3 suites carry no key exchange: take the group from the key_share extension.
- Forward secrecy: TLS 1.3 yes. TLS 1.2 yes for ECDHE/DHE suites, no for static RSA or static DH. null if the handshake is incomplete.
- Also record SNI, ALPN, offered cipher count, extension list and order, supported groups, and JA3/JA3S when tshark exposes them (check the installed version).

## Certificates
- TLS 1.2 and earlier: the certificate chain is visible in the Certificate handshake message.
- TLS 1.3 encrypts the certificate. Report `certificate_observable: false` with a note. Never fabricate, never treat it as missing or bad. Resumed sessions carry no certificate either.
- Parse with the Python `cryptography` package. Record subject, issuer, validity, days to expiry, self-signed, key algorithm and size or curve, signature algorithm, SAN, SHA-256 fingerprint.
- Chain validation: build the chain from what the server sent, verify each signature, check whether it anchors to a trusted root store (certifi or the system store), check hostname against SNI when SNI is present. Missing intermediates are a distinct finding from an untrusted root. Use the library's verification API if the installed version has it, otherwise verify signatures explicitly.

## Weak or deprecated crypto (data-driven)
Keep rules in `rules/tls_rules.yaml` with id, title, condition, severity, category, references. Starting set: SSLv2/SSLv3, TLS 1.0, TLS 1.1 (RFC 8996); RC4 (RFC 7465); 3DES/64-bit block; export, NULL and anonymous suites; no forward secrecy; static-RSA key exchange; RSA below 2048 bits; DH parameters below 2048 bits when visible; MD5 or SHA-1 signatures; expired or not-yet-valid certificate; self-signed on a public-facing server; hostname mismatch; STARTTLS-only mailbox access where implicit TLS is available (RFC 8314). Sources to cite: NIST SP 800-52 Rev. 2, RFC 9325, RFC 8996, RFC 7465, RFC 8314. Check these are still current before quoting them.

## Rules
- Every finding carries evidence: session id, frame numbers, endpoints, and a Wireshark display filter (`tcp.stream eq N`).
- A field that could not be observed is null. It is never scored as good.
- Truncated or mid-stream captures are reported as partial sessions with what is known.
