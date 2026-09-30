# SecureMailScope API Contract

Version: 0.1
Changelog:
- 0.1 initial draft

Conventions: JSON, snake_case, ISO 8601 UTC timestamps. `null` means not observable or not applicable. Enums are closed. Errors: `{"detail": "safe message"}`.

## Endpoints
| Method | Path | Notes |
|---|---|---|
| GET | /health | 200 {"status":"ok"}, no work |
| POST | /api/captures | multipart `file`; 202 {capture_id, status} |
| GET | /api/captures | list of Capture (with posture_score, grade) |
| GET | /api/captures/{id} | Capture |
| DELETE | /api/captures/{id} | remove capture and derived data |
| GET | /api/captures/{id}/summary | Summary |
| GET | /api/captures/{id}/sessions?protocol=&transport=&page=&page_size= | paged Session list |
| GET | /api/captures/{id}/sessions/{sid} | Session detail |
| GET | /api/captures/{id}/findings?severity=&category=&protocol= | Finding list ordered by priority_rank |
| GET | /api/drift?baseline={id}&current={id} | Drift |
| GET | /api/captures/{id}/report?format=json\|html\|pdf | file download |

## Types
Capture: id, filename, sha256, size_bytes, packet_count, duration_s, status (queued|processing|complete|failed), error, created_at, posture_score (0-100 or null until complete), grade (A-F or null).

Summary: posture {score, grade, factors[{name, weight, impact, detail, finding_ids[]}]}, severity_counts {critical, high, medium, low, info}, protocol_counts {smtp, imap, pop3, unknown}, transport_counts {implicit_tls, starttls, plaintext}, limitations[str], baseline_status (ok|insufficient|not_configured).

Session: id, protocol (smtp|imap|pop3|unknown), protocol_confidence (high|low), client, server, server_port, transport (implicit_tls|starttls|plaintext), starttls {advertised, initiated, succeeded, downgrade_suspected} (booleans, succeeded nullable), auth_before_tls (bool|null), tls (null or {version, cipher_suite, key_exchange, forward_secrecy (bool|null), sni, alpn, ja3, ja3s}), certificate_observable (bool), certificate_note (str|null), certificate_chain (list of Certificate|null), message_layer {state (encrypted|signed|none_observed|not_observable), markers[{type, count}]}, first_frame, last_frame, wireshark_filter, findings_count.

Certificate: subject, issuer, not_before, not_after, days_to_expiry, expired, self_signed, key_algorithm, key_bits, signature_algorithm, san[str], sha256_fingerprint, chain_valid (bool|null), hostname_match (bool|null), validation_notes[str].

Finding: id, session_id (null for capture-level), rule_id, title, severity (critical|high|medium|low|info), category (transport|certificate|protocol|message|anomaly|drift), description, evidence {frames[int], client, server, server_port, certificate_sha256 (nullable)}, wireshark_filter, score_impact, priority_rank, context {server_role (inbound_relay|submission|mailbox|unknown), sessions_affected, clients_affected}, anomaly {deviating_features[{feature, observed, baseline}]} (only for category anomaly), remediation {summary, steps[str], references[str]}.

Drift: baseline_capture_id, current_capture_id, changes[{server, kind (tls_version|cipher_suite|key_exchange|certificate|starttls|auth_before_tls|endpoint), before, after, direction (improved|degraded|changed|appeared|disappeared), severity}].
