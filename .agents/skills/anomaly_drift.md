# Skill: anomaly_drift

## Behavioral TLS fingerprinting
1. Per session features: negotiated version, cipher suite, offered cipher count and order, extension list and order, supported groups, signature algorithms, ALPN, SNI present, certificate key size and validity length, ClientHello to ServerHello time, JA3/JA3S if available.
2. Baseline: learn "normal" per server endpoint (and per client population) from a designated baseline capture or the first N sessions.
3. Method: with roughly 50 or more baseline sessions, an Isolation Forest (scikit-learn) on encoded features. With fewer, categorical rarity rules (a value never seen in the baseline, or below 5 percent). With too few to say anything, report "baseline insufficient" and emit no anomalies.
4. Every anomaly names the features that deviated and by how much. An anomaly without an explanation is not emitted.
5. Anomalies are category `anomaly`, severity low or medium, worded as "unusual compared with baseline", not as "vulnerable" or "attack".

## Cryptographic drift
Compare two captures per server endpoint (ip:port): TLS version, cipher suite, key exchange group, certificate fingerprint and expiry, STARTTLS behaviour, authentication before TLS.
- direction: improved, degraded, changed.
- A new certificate with the same subject and issuer is a rotation (info). A different issuer or a shrinking key size is a degradation.
- Endpoints present in only one capture are listed as appeared or disappeared.

## Rules
- Fixed random seeds and pinned model settings, so the same capture gives the same result.
- Never claim the anomaly detector finds attacks. It flags deviation from a learned baseline.
- Evaluate on the ground-truth captures: the clean capture yields no anomalies, the injected-deviation capture yields the planted ones.
