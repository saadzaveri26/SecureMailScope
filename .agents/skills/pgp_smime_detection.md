# Skill: pgp_smime_detection

## Purpose
Assess message-level encryption alongside transport security, honestly and passively.

## What is observable
Message content is visible only where it crosses the wire in cleartext: SMTP DATA on a plaintext or pre-STARTTLS session, IMAP FETCH or POP3 RETR on plaintext. Inside TLS it is invisible. Optionally accept exported .eml files as a second input for message-layer checks.

## Markers
- OpenPGP armor: `-----BEGIN PGP MESSAGE-----`, `-----BEGIN PGP SIGNED MESSAGE-----`, `-----BEGIN PGP PUBLIC KEY BLOCK-----`.
- PGP/MIME (RFC 3156): `multipart/encrypted; protocol="application/pgp-encrypted"`, `multipart/signed; protocol="application/pgp-signature"`.
- S/MIME: `application/pkcs7-mime` and `application/x-pkcs7-mime` (enveloped-data or signed-data), `application/pkcs7-signature`.
- Autocrypt header as a capability hint.

## Output
Per session: message_layer = encrypted | signed | none_observed | not_observable, with marker type, count, frame numbers. Store markers only. Never store bodies, keys, or signatures.

## Findings and score
- Cleartext message with no message-layer protection on a plaintext transport: high.
- Message-layer encryption present: positive factor (defense in depth), capped, and it does not offset transport findings.
- Everything inside TLS: report "message-level encryption not observable". Do not report it as absent.
- Informational recommendation: PGP and S/MIME do not protect headers such as Subject, so keep transport TLS as well.

## Rules
- Never decrypt, never attempt key recovery.
- Because this feature is the first cut candidate, keep it isolated in its own module and its own contract fields so removing it breaks nothing.
