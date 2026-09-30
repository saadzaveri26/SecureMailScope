"""Rule metadata: title, severity, why-it-matters, remediation and copy-paste config hints."""
from __future__ import annotations

SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

RULES: dict[str, dict] = {}


def _r(rid, title, sev, cat, desc, why, fix, effort="medium", refs=(), hints=None):
    RULES[rid] = {"rule_id": rid, "title": title, "severity": sev, "category": cat, "description": desc, "why_it_matters": why,
                  "remediation": list(fix), "effort": effort, "references": list(refs), "config_hints": hints or {}}


H_TLS = {"postfix": "smtpd_tls_mandatory_protocols = >=TLSv1.2\nsmtpd_tls_protocols = >=TLSv1.2\nsmtp_tls_protocols = >=TLSv1.2",
         "dovecot": "ssl_min_protocol = TLSv1.2",
         "exim": "openssl_options = +no_sslv2 +no_sslv3 +no_tlsv1 +no_tlsv1_1"}
H_CIPHER = {"postfix": "smtpd_tls_mandatory_ciphers = high\nsmtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, 3DES",
            "dovecot": "ssl_cipher_list = ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM\nssl_prefer_server_ciphers = yes",
            "exim": "tls_require_ciphers = ECDHE+AESGCM:ECDHE+CHACHA20"}
H_STARTTLS = {"postfix": "smtpd_tls_security_level = may   # MX (port 25)\nsmtpd_tls_security_level = encrypt   # submission (587)\nsmtpd_tls_auth_only = yes",
              "dovecot": "ssl = required\ndisable_plaintext_auth = yes",
              "exim": "tls_advertise_hosts = *\nauth_advertise_hosts = ${if eq{$tls_in_cipher}{}{}{*}}"}
H_DH = {"postfix": "tls_ffdhe_auto_groups = ffdhe2048:ffdhe3072   # or: openssl dhparam -out /etc/postfix/dh2048.pem 2048",
        "dovecot": "ssl_dh = </etc/dovecot/dh.pem   # openssl dhparam -out /etc/dovecot/dh.pem 3072"}
RFC8996 = "RFC 8996 (Deprecating TLS 1.0/1.1)"
BCP195 = "RFC 9325 / BCP 195 (TLS recommendations)"

# ---- transport / STARTTLS
_r("TR-001", "Credentials exchanged in cleartext", "CRITICAL", "transport",
   "Mailbox credentials (AUTH PLAIN/LOGIN, IMAP LOGIN, POP3 USER/PASS) were sent over an unencrypted session.",
   "Anyone on the path can passively read usernames and passwords; the account must be treated as compromised.",
   ["Require TLS before authentication (disable plaintext auth).", "Force password resets for the exposed accounts.",
    "Block cleartext ports (110/143/25 auth) at the firewall for client access."], "low",
   ["RFC 8314 (Cleartext considered obsolete)"], H_STARTTLS)
_r("TR-002", "Email session without transport encryption", "HIGH", "transport",
   "The session carried mail traffic without any TLS.", "Message content and metadata are readable and modifiable in transit.",
   ["Enable STARTTLS or implicit TLS on this service.", "Enforce encryption for submission/IMAP/POP3; use MTA-STS/DANE for MX traffic."],
   "low", ["RFC 3207", "RFC 8461 (MTA-STS)"], H_STARTTLS)
_r("TR-003", "STARTTLS upgrade refused - possible stripping / downgrade", "CRITICAL", "transport",
   "The client requested STARTTLS/STLS but the server (or an on-path device) answered with an error and the session continued in cleartext.",
   "This is the signature of a STARTTLS stripping attack or a broken TLS configuration; traffic is exposed.",
   ["Investigate middleboxes/proxies on the path that may rewrite STARTTLS responses.", "Configure clients to require TLS (never fall back to plaintext).",
    "Check server logs for TLS initialisation failures."], "medium", ["CVE-2011-0411", "RFC 7817"], H_STARTTLS)
_r("TR-004", "Plaintext injected before TLS handshake (STARTTLS command injection)", "HIGH", "transport",
   "Client plaintext commands were buffered after the STARTTLS command and before the handshake.",
   "The STARTTLS injection bug class lets an attacker inject commands executed inside the encrypted session.",
   ["Update the mail server to a version that discards buffered plaintext after STARTTLS.", "Inspect the client sending pipelined commands."],
   "medium", ["CVE-2011-0411", "CVE-2011-1430"])
_r("TR-005", "Authentication mechanisms offered before TLS", "MEDIUM", "transport",
   "Server advertised cleartext-capable authentication (PLAIN/LOGIN/USER-PASS) in the unencrypted phase.",
   "Clients may authenticate before upgrading to TLS and leak credentials.",
   ["Only advertise AUTH after TLS is established.", "IMAP: enable LOGINDISABLED until STARTTLS."], "low", [], H_STARTTLS)

# ---- protocol version
_r("TLS-001", "Deprecated protocol version negotiated", "HIGH", "protocol",
   "The session negotiated SSLv3 / TLS 1.0 / TLS 1.1.", "Deprecated protocols are vulnerable to POODLE/BEAST-class attacks and lack modern AEAD/PFS guarantees.",
   ["Disable TLS < 1.2 on the server.", "Identify and upgrade/replace the client that only supports legacy TLS."], "low", [RFC8996], H_TLS)
_r("TLS-002", "TLS handshake failed or fatal alert observed", "LOW", "protocol",
   "A fatal alert or an incomplete handshake was seen.", "Repeated failures can indicate probing, misconfiguration or an active downgrade attempt.",
   ["Review server TLS logs for the client.", "Check protocol/cipher overlap between client and server."], "low")
_r("TLS-003", "TLS downgrade sentinel present in ServerHello", "HIGH", "protocol",
   "Server random carries the TLS 1.3 downgrade sentinel: the server supports TLS 1.3 but a lower version was negotiated.",
   "Indicates the client (or an on-path attacker) forced a downgrade.", ["Investigate the client and path for interception.", "Ensure clients enable TLS 1.3."],
   "medium", ["RFC 8446 section 4.1.3"])
_r("TLS-004", "Client offers deprecated protocol versions", "LOW", "protocol",
   "The ClientHello advertises SSLv3 / TLS 1.0 / TLS 1.1.", "The server may accept a weak version if not restricted.", ["Update client TLS settings to TLS 1.2+."], "low", [RFC8996])
_r("TLS-005", "Client protocol fallback (TLS_FALLBACK_SCSV)", "MEDIUM", "protocol",
   "Client signalled a fallback retry with a lower protocol version.", "Fallback often follows a failed handshake and is a classic downgrade-attack vector.",
   ["Investigate why the higher-version handshake failed."], "medium", ["RFC 7507"])
_r("TLS-006", "TLS compression negotiated", "HIGH", "protocol", "ServerHello selected a compression method.",
   "TLS compression enables CRIME-style plaintext recovery.", ["Disable TLS compression (OpenSSL: SSL_OP_NO_COMPRESSION)."], "low", ["CVE-2012-4929"])
_r("TLS-007", "Secure renegotiation not supported", "MEDIUM", "protocol",
   "Server did not include renegotiation_info (RFC 5746).", "Vulnerable to the TLS renegotiation prefix-injection attack.",
   ["Upgrade the TLS library / mail server.", "Disable insecure renegotiation."], "medium", ["CVE-2009-3555", "RFC 5746"])
_r("TLS-008", "Extended master secret not negotiated (TLS 1.2)", "LOW", "protocol",
   "Handshake lacks the extended_master_secret extension.", "Enables triple-handshake style session-binding attacks.",
   ["Update TLS stack to support RFC 7627."], "medium", ["RFC 7627"])
_r("TLS-009", "TLS heartbeat extension enabled", "LOW", "protocol", "Server negotiated the heartbeat extension.",
   "Heartbeat is unnecessary for mail and was the vector for Heartbleed.", ["Verify OpenSSL is patched and disable heartbeat."], "low", ["CVE-2014-0160"])
_r("TLS-010", "TLS 1.3 not enabled on server", "LOW", "protocol", "Client offered TLS 1.3 but TLS 1.2 was negotiated (no downgrade marker).",
   "TLS 1.3 removes legacy cryptography, encrypts the certificate and shortens the handshake.", ["Enable TLS 1.3 on the server."], "low", [], H_TLS)

# ---- cipher suites / key exchange
_r("CS-001", "Insecure cipher suite negotiated", "CRITICAL", "cipher",
   "A NULL / EXPORT / anonymous / RC4 / DES / MD5-based suite was negotiated.", "Traffic can be decrypted or modified with little effort.",
   ["Remove insecure suites from the server cipher list immediately."], "low", ["RFC 7465", "FREAK/Logjam"], H_CIPHER)
_r("CS-002", "Weak cipher suite negotiated (3DES)", "HIGH", "cipher", "3DES was negotiated.", "64-bit block ciphers are exposed to Sweet32 birthday attacks.",
   ["Disable 3DES suites."], "low", ["CVE-2016-2183"], H_CIPHER)
_r("CS-003", "CBC-mode cipher suite negotiated", "LOW", "cipher", "A CBC suite was negotiated.", "CBC has a long history of padding-oracle attacks (Lucky13).",
   ["Prefer AEAD suites (AES-GCM / ChaCha20-Poly1305)."], "low", [BCP195], H_CIPHER)
_r("CS-004", "No forward secrecy", "MEDIUM", "cipher", "The key exchange was static RSA/DH (no ephemeral keys).",
   "A future private-key compromise decrypts all recorded traffic (harvest-now-decrypt-later).", ["Prioritise ECDHE/DHE suites; drop static RSA key exchange."], "low", [BCP195], H_CIPHER)
_r("CS-005", "Client offers insecure or weak cipher suites", "LOW", "cipher", "ClientHello lists NULL/EXPORT/RC4/DES/3DES suites.",
   "If the server accepts them the session can be weakened.", ["Reconfigure the client crypto policy."], "low")
_r("CS-006", "Weak Diffie-Hellman parameters", "HIGH", "cipher", "DHE prime is shorter than 2048 bits.", "1024-bit DH is within reach of nation-state precomputation (Logjam).",
   ["Generate/use >=2048-bit (ideally ffdhe3072) DH groups or prefer ECDHE."], "low", ["Logjam (CVE-2015-4000)"], H_DH)
_r("CS-007", "Weak elliptic curve group", "MEDIUM", "cipher", "A curve below 224 bits was used.", "Insufficient security margin.",
   ["Restrict groups to x25519, secp256r1, secp384r1."], "low")
_r("CS-008", "SHA-1 signature in key exchange", "MEDIUM", "cipher", "ServerKeyExchange is signed with a SHA-1/MD5 based algorithm.", "Collision attacks weaken handshake authentication.",
   ["Use sha256+ signature algorithms (rsa_pss / ecdsa_sha256)."], "medium")
_r("CS-009", "No post-quantum hybrid key exchange", "INFO", "cipher", "Session key exchange is classical only.",
   "Recorded traffic could be decrypted by a future quantum adversary.", ["Plan migration to hybrid X25519MLKEM768 where supported."], "high", ["NIST FIPS 203"])

# ---- certificates
_r("CE-001", "Server certificate expired", "HIGH", "certificate", "Certificate validity ended before the capture.", "Clients cannot authenticate the server; users are trained to click through warnings.",
   ["Renew and deploy a new certificate.", "Automate renewal (ACME)."], "low")
_r("CE-002", "Server certificate not yet valid", "HIGH", "certificate", "notBefore is later than the capture time.", "Indicates a wrong system clock or a mis-issued certificate.",
   ["Check server/client clocks and the certificate."], "low")
_r("CE-003", "Server certificate expiring soon", "MEDIUM", "certificate", "Certificate expires within 30 days of capture.", "Expiry causes service outage and validation failures.",
   ["Renew the certificate now.", "Add expiry monitoring/alerts."], "low")
_r("CE-004", "Self-signed server certificate", "MEDIUM", "certificate", "Leaf certificate is self-signed and not in the trust store.", "Clients cannot validate identity; MITM is undetectable.",
   ["Issue a certificate from a trusted or enterprise CA."], "medium")
_r("CE-005", "Certificate chain not trusted", "HIGH", "certificate", "Chain does not anchor to a trusted root.", "Clients will reject or bypass validation.",
   ["Install a certificate from a trusted CA and serve the full chain.", "Add your enterprise CA to production_artifacts/trust_store/ if private."], "medium")
_r("CE-007", "Invalid certificate chain linkage", "HIGH", "certificate", "A certificate is not signed by the next one in the chain.", "Broken or forged chain.", ["Rebuild the chain bundle in correct order."], "low")
_r("CE-008", "Weak RSA key length", "HIGH", "certificate", "RSA key is shorter than 2048 bits.", "Keys <2048 bits can be factored with feasible resources.", ["Re-issue with RSA >=2048 (3072 recommended) or ECDSA P-256."], "medium", ["NIST SP 800-57"])
_r("CE-009", "Weak EC key", "HIGH", "certificate", "EC key smaller than 224 bits.", "Insufficient security margin.", ["Re-issue with P-256/P-384."], "medium")
_r("CE-010", "Weak certificate signature algorithm", "HIGH", "certificate", "Certificate signed with MD5/SHA-1.", "Collision attacks enable certificate forgery.", ["Re-issue with SHA-256+ signature."], "medium", ["CA/B Forum baseline requirements"])
_r("CE-011", "Certificate hostname mismatch", "HIGH", "certificate", "SNI requested by the client is not covered by the certificate SAN/CN.", "Validation failure or on-path interception with a substitute certificate.",
   ["Issue a certificate covering the service hostname.", "Check for TLS interception devices."], "medium", ["RFC 6125"])
_r("CE-012", "Excessive certificate validity period", "LOW", "certificate", "Leaf validity exceeds 825 days.", "Long-lived certificates increase key-compromise exposure.", ["Use <=398-day certificates with automated renewal."], "low")
_r("CE-013", "Certificate lacks Subject Alternative Name", "LOW", "certificate", "Only CN is present.", "CN-only matching is deprecated.", ["Re-issue with SAN entries."], "low", ["RFC 2818"])
_r("CE-014", "DSA public key in certificate", "MEDIUM", "certificate", "DSA keys are deprecated.", "Not supported by modern stacks and weak in practice.", ["Migrate to RSA/ECDSA."], "medium")
_r("CE-015", "Intermediate certificate expired", "HIGH", "certificate", "An intermediate in the chain has expired.", "Validation fails on strict clients.", ["Replace the intermediate bundle."], "low")
_r("CE-016", "Server certificate not observable (TLS 1.3)", "INFO", "certificate", "TLS 1.3 encrypts the Certificate message; passive chain validation is impossible.",
   "Certificate posture for these sessions must be inferred from TLS <=1.2 sessions or active scanning.", ["Complement with an active scan (openssl s_client / testssl.sh) for the endpoint."], "low")

# ---- message layer
_r("MS-001", "Message-level encryption/signing observed (PGP / S-MIME)", "INFO", "message", "OpenPGP or S/MIME protected content was detected.",
   "Message-level protection complements transport security (end-to-end confidentiality).", ["Keep key hygiene policies; combine with TLS."], "low")
_r("MS-002", "Message-level protection over plaintext transport", "MEDIUM", "message", "PGP/S-MIME content travels over an unencrypted channel.",
   "Bodies are protected but headers, addresses and metadata are exposed.", ["Enable TLS in addition to message-level encryption."], "low")
_r("MS-003", "S/MIME uses weak hash or weak signer certificate", "MEDIUM", "message", "S/MIME signature micalg or signer certificate is weak.", "Signatures can be forged.", ["Re-issue S/MIME certificates with SHA-256+ and RSA>=2048."], "medium")
_r("MS-004", "OpenPGP message without integrity protection", "MEDIUM", "message", "Symmetrically-encrypted data packet without MDC (tag 9).", "Ciphertext can be modified undetected (EFAIL class).",
   ["Use AEAD/SEIPD packets; update PGP clients."], "medium", ["EFAIL (CVE-2017-17688)"])

# ---- ML
_r("ML-001", "Anomalous TLS session behaviour (ML)", "MEDIUM", "anomaly", "Isolation Forest flagged sessions whose cryptographic/handshake behaviour deviates from the reference profile.",
   "Deviations from an established baseline often precede or accompany downgrade, MITM, or misconfiguration events.",
   ["Review the listed sessions and the deviating features.", "Compare with server change records for the period."], "medium")
