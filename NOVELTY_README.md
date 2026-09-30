# SecureMailScope - Novelty & What Is New

The problem statement (NTRO #26159) already asks for PCAP parsing, TLS/certificate analysis, ML risk scoring, anomaly
detection, prioritised findings and reports. Those are the **baseline requirements** and are all implemented.
This document lists what goes **beyond** them.

---

## 1. Cryptographic Baseline & Drift Detection Engine  *(headline novelty)*

Existing tools (Wireshark, tshark, testssl.sh, Zeek) answer *"is this configuration weak right now?"*.
SecureMailScope also answers **"what changed, where, how many sessions, why does it matter, and what should I investigate?"**

```
PCAP #1 (known-good) -> Cryptographic Analyzer -> BASELINE PROFILE  (TLS / cipher / key-exchange / certificate / transport / fingerprint)
PCAP #2 (later)      -> Cryptographic Analyzer -> Drift Engine  --compare-->  baseline
                                                        |
                              TLS drift | Cipher drift | Certificate drift | Transport (STARTTLS) drift | Fingerprint | Latency
```

| Capability | Detail |
|---|---|
| Per-endpoint baseline profiles | Version/cipher/kex distributions, PFS ratio, certificate set, STARTTLS-offer ratio, JA3S set, handshake latency; SHA-256 integrity hash; versioned history (`baselines/history/`) |
| Structured drift items | `what_changed`, `baseline` vs `current`, `affected_sessions`, TCP-stream **evidence** (stream id, handshake message, negotiated value), `why_it_matters`, `recommendation` |
| Certificate drift intelligence | Distinguishes *likely renewal* (LOW) from *unscheduled replacement* (MEDIUM) from *issuer / key / signature downgrade or concurrent old+new certs* (HIGH) |
| STARTTLS-stripping detection | Cross-session: baseline always offered STARTTLS, now sessions are plaintext -> CRITICAL. In-session: STARTTLS refused (`454`/`-ERR`/`NO`) then continues with AUTH in cleartext |
| Distribution shift metrics | Jensen-Shannon divergence per dimension (TLS, cipher, kex, transport), drift score 0-100 |
| Posture change | Baseline vs current score per endpoint -> `DEGRADED / STABLE / IMPROVED` |
| New / vanished endpoint notes | Flags mail endpoints not in the baseline (shadow IT / rogue MTA) |
| Recompute on demand | `POST /analyses/{id}/drift/recompute` after (re)baselining |

Sample output (from the bundled demo, `securemail_drift.pcap` vs baseline):
`TLS 1.1 traffic detected | Baseline: TLS 1.2 / TLS 1.3 only | Current: TLS 1.1 / 1.2 / 1.3 | Affected sessions: 14 | HIGH | Evidence: stream 97, ServerHello, negotiated_version=TLS 1.1`

## 2. Baseline-trained anomaly detection (drift-aware ML)

* **Isolation Forest per endpoint, trained on the known-good baseline** and used to score later captures - deviations from *that server's* normal behaviour, not from a generic idea of normal. Falls back to self-fit when no baseline exists.
* 29 session features: version, grade, kex, PFS, AEAD, key bits, handshake time, packets/retransmissions/volume, certificate validity/key/self-signed/chain length, client hello shape, alerts, resumption, downgrade sentinel, and **rarity of the handshake message sequence / JA3 / JA3S** (learned from the reference set).
* **Explained anomalies**: every flagged session lists the deviating features with reference frequencies, e.g. *"Negotiated TLS version = TLS 1.1 (seen in 0.0% of reference sessions)"*. A session is only "anomalous" if the score is high **and** at least one human-readable reason exists (this removed false positives from network noise in testing).
* ML never *lowers* risk; it can only raise it (`risk = 1-(1-rule)(1-0.5*ml)`), so the deterministic rules stay authoritative.

## 3. Explainable Security Assessment (per session)

Instead of an opaque score, each session yields a card: TLS version / cipher / key exchange / certificate / transport / ML score rows with OK-WARN-FAIL status, a **"WHY?"** list and a **recommendation** (`GET /analyses/{id}/sessions/{sid}`), reproduced in the HTML/PDF reports.

## 4. Unified transport + message-layer posture (mentor's addition)

* **OpenPGP**: armored MESSAGE / SIGNED / SIGNATURE / PUBLIC KEY blocks, PGP/MIME, and *packet-level* inspection (public-key algorithm of the PKESK, detection of **symmetrically-encrypted data without MDC** -> EFAIL-class finding).
* **S/MIME**: enveloped vs signed, `micalg` weakness (MD5/SHA-1), **signer certificates extracted from the PKCS#7 blob and analysed** with the same X.509 engine.
* **Layer correlation**: "message-level protection over plaintext transport" (bodies safe, metadata exposed) - a finding neither layer would raise alone.

## 5. Detections that go beyond "weak cipher / old TLS"

44 rules across transport, protocol, cipher, certificate, message and anomaly categories, including:

* STARTTLS **command injection** (CVE-2011-0411 class): plaintext buffered after `STARTTLS`.
* TLS **downgrade sentinel** (`DOWNGRD`) in ServerHello.random and `TLS_FALLBACK_SCSV` fallbacks.
* Weak DHE (**Logjam**) from `ServerKeyExchange`, weak curves, SHA-1 handshake signatures, compression (CRIME), missing secure-renegotiation / EMS, heartbeat.
* **Post-quantum readiness**: detects hybrid ML-KEM / Kyber key shares and reports a PQ-hybrid ratio (harvest-now-decrypt-later exposure).
* Cleartext-credential exposure with **masked** username (passwords never stored).
* JA3 / JA3S fingerprints for client/server stack identification.

## 6. Engineering novelty

| Item | Why it matters |
|---|---|
| **Pure-Python passive dissector** (dpkt + own TLS/handshake parser) - no tshark dependency | Runs anywhere, reproducible, fully testable; handles retransmission, reordering, sequence wrap, port reuse, PCAPNG, VLAN/SLL/loopback link types |
| **Enterprise trust store** (`production_artifacts/trust_store/`) on top of the Mozilla bundle | Private-CA mail infrastructure validates correctly instead of producing false "untrusted" alarms |
| **Honest TLS 1.3 handling** | TLS 1.3 encrypts certificates; the tool reports `certificate not observable` (INFO) instead of guessing, and builds certificate posture from TLS<=1.2 sessions |
| **Threat prioritisation** | `priority = severity base + 30*exposure + context bonuses` -> P1..P4, quick-win flag, and a de-duplicated **remediation plan** |
| **Copy-paste remediation** | Postfix / Dovecot / Exim configuration hints attached to rules |
| **Forensic soundness** | SHA-256 chain-of-custody of the PCAP, tool version, baseline integrity hash, limitations section in every report |
| **Synthetic scenario generator** | `tools/generate_sample_pcaps.py` builds baseline + regression captures (STARTTLS stripping, TLS 1.0/1.1, RC4, 3DES, rogue-CA cert, Logjam, PGP/S-MIME) so the whole system is demonstrable without a mail server |

## 7. Honest limitations

* Passive analysis cannot decrypt content; PGP/S-MIME detection applies to plaintext streams.
* Revocation (OCSP/CRL) is not checked offline.
* Drift quality depends on the baseline being captured during a healthy period (the API warns when it isn't).
* ML scores are indicators, not proof; correlate with rule findings and change records.
