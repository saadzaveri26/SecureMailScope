# SecureMailScope Contract 0.2 Spec

Additive to 0.1. No 0.1 field is removed or renamed. `null` still means not observable or not applicable. Enums are closed. Each item is tagged with a tier:
- [A] required now, blocks everything else
- [B] required after the core pipeline works
- [C] stretch, only if A and B are done

Claims rule: this tool produces an integrity record and audit trail. It does not claim legal admissibility. The asset inventory is what was observed, not what a server supports.

## 1. Access and actor [A]
- Every /api route except GET /health requires header `X-Access-Token`. Missing or wrong: 401 `{"detail": "..."}`.
- Routes that change state also require `X-Actor` (non-empty, at most 64 characters). The actor is self-asserted. It is recorded in the audit trail and is not proof of identity.
- The frontend asks for the token and actor name at runtime, keeps them in sessionStorage, and never bakes them into the bundle or a NEXT_PUBLIC variable.
- Report downloads use fetch with headers and a blob, not a plain link.

## 2. Integrity record and custody [A]
Capture gains:
- `custody`: {sha256, original_filename, size_bytes, received_at, uploaded_by, payload_retained (bool), payload_deleted_at (timestamp|null)}
- `analysis`: {tool_version, ruleset_version, ruleset_sha256, modes (["passive"] plus any of "key_assisted", "artifact_assisted"), started_at, completed_at}

New: `GET /api/captures/{id}/custody` returns CustodyEvent[]: {id, ts, actor, action (uploaded|analysis_started|analysis_completed|report_exported|triage_changed|payload_deleted|keylog_attached|artifact_attached), detail}.
- Append-only. No update or delete route exists for custody events.
- The hash and metadata survive deletion of the uploaded payload.
- UI label: "Integrity record and audit trail".

## 3. Evidence chain [A]
Chain: capture (hash) -> session -> evidence -> finding (rule) -> remediation.
Evidence: {id, capture_id, type (session|starttls_exchange|handshake|certificate|cleartext_auth|message_marker|baseline_deviation), session_id (nullable), frames[int], summary (plain text, at most 200 chars), wireshark_filter, certificate_sha256 (nullable)}.
- id is deterministic: "EV-" plus the first 8 hex characters of sha256(capture_sha256 + type + session_id + joined frames).
- Evidence never contains payload content. The summary is built from parsed fields only.
- New: `GET /api/captures/{id}/evidence` and `GET /api/captures/{id}/evidence/{eid}`.
- Finding gains `evidence_ids[]`. Every finding has at least one, except capture-level limitation findings, which state that none apply. The inline `evidence` object from 0.1 stays.

## 4. Rules and policy [A]
- `GET /api/rules` returns Rule[]. `GET /api/rules/version` returns {ruleset_version, sha256}.
- Rule: {id, version, title, description, severity, category, enabled, policy_refs[{document, section, verified_on (date)}]}.
- A policy_ref is included only after the section was checked against the current document. `verified_on` records when. No unchecked citations.
- Finding gains `rule_version` and `policy_refs`.

## 5. Severity and confidence [A]
Finding gains `confidence` (high|medium|low) and `confidence_basis` (string[]).
- high: full handshake or full application-layer exchange observed.
- medium: partial capture, mid-stream capture, or inference from a consistent subset.
- low: indirect or heuristic, for example suspected STARTTLS stripping inferred across sessions, and all baseline-deviation findings.
- Confidence never changes severity.
- `config/scoring.yaml` holds confidence_weight {high: 1.0, medium: 0.75, low: 0.5}, used for score impact and for priority_rank. Document the reason next to each value.

## 6. Observability [A]
Session gains `visibility`: {handshake (complete|partial|none), certificate (observable|hidden_tls13|resumed|not_seen), message_layer (observable|hidden_by_tls|not_applicable), partial_capture (bool), reasons[string]}.
- `certificate_observable` from 0.1 stays and must equal (visibility.certificate == "observable"). The backend asserts this and fixtures must follow it.
Summary gains `visibility`: {sessions_total, handshake_complete, handshake_partial, certificate_observable, certificate_hidden_tls13, certificate_resumed, message_layer_observable, plaintext_sessions, checks_not_performed[{check, reason, sessions}]}.
- UI: a panel titled "What this capture could and could not see" on Overview.

## 7. Evaluation [A]
`GET /api/evaluation` returns {corpus_version, ruleset_version, run_at, captures, per_rule[{rule_id, expected, detected, tp, fp, fn, precision (nullable), recall (nullable)}], overall {precision, recall}, clean_capture_false_alarms, label}.
- label is always: "Measured against the synthetic lab corpus. Not a claim about real-world accuracy."
- Served from the last run of the evaluation script. The UI page is called Evaluation.

## 8. Report additions [A]
The JSON report adds: custody, analysis, rules used (ids and versions), evidence[], findings with confidence and evidence_ids and policy_refs, visibility, limitations, evaluation reference (corpus_version). With [B] present it also adds incidents, assets and triage. HTML and PDF mirror the JSON. Each report ends with the integrity record: SHA-256, tool version, ruleset version and hash, UTC timestamps.

## 9. Endpoint inventory [B]
`GET /api/captures/{id}/assets` returns Asset[]: {id ("ip:port"), server, port, protocols[], server_role, tls_versions_observed[], cipher_suites_observed[], key_exchange_groups_observed[], forward_secrecy (all|some|none|unknown), starttls_support (always|sometimes|never|not_applicable), certificates[{sha256, subject, issuer, not_after, key_algorithm, key_bits, signature_algorithm}], sessions_observed, clients_observed, first_seen, last_seen, pqc (see section 12)}.
- Label in the UI: "Observed". Never "supported".

## 10. Incidents and triage [B]
Incident: {id, rule_id, title, server, server_role, severity (highest), confidence (lowest), sessions_affected, clients_affected, first_seen, last_seen, finding_ids[], evidence_ids[], state (open|under_investigation|confirmed|false_positive|accepted_risk|remediated), priority_rank, remediation}.
- Grouping rule: same server (ip:port) and same rule_id. id is "INC-" plus the first 8 hex of sha256(capture_sha256 + server + rule_id).
- Finding gains `incident_id`.
- `GET /api/captures/{id}/incidents?state=&severity=`.
- `PATCH /api/incidents/{id}/state` body {state, note}. The note is required for false_positive and accepted_risk. Writes a TriageEvent and a custody event.
- `GET /api/incidents/{id}/history` returns TriageEvent[]: {id, ts, actor, from_state, to_state, note}.
- Score: `posture.score` never changes. Summary.posture gains `triaged_score` and `triage_adjustments[{incident_id, state, effect}]`. Only false_positive removes its penalty from triaged_score. accepted_risk and remediated do not. A remediated state is confirmed by a later capture, not by the analyst.
- Triage state belongs to one capture. Carrying it across captures is roadmap.

## 11. Drift [B]
- Pin a baseline: `PUT /api/baseline` body {capture_id}. Read: `GET /api/baseline`.
- `GET /api/drift?current=&baseline=`. baseline is optional if one is pinned. 404 if neither exists.
- Drift change `kind` gains `issuer` and `key_size`.

## 12. Stretch [C]
PQC (informational only): Asset.pqc = {hybrid_groups_offered_by_clients (bool|null), hybrid_group_negotiated (bool|null), groups_seen[], classical_public_key_in_chain (bool|null), note}. No score impact. Severity info at most. Framed as exposure of long-retained mail, never as "vulnerable today". Check group names against the IANA TLS Supported Groups registry and the installed tshark before use.

Analysis modes:
- `GET /api/features` returns {key_assisted (bool), artifact_assisted (bool)}.
- POST /api/captures accepts optional multipart `keylog` (SSLKEYLOGFILE format) and `artifact` (PEM certificate chain), plus an `authorised` field that must be true when a keylog is sent.
- key_assisted is behind a server flag that defaults to off. Pass the keylog to tshark with the TLS keylog preference (name varies by version, check the installed one). Store the keylog only for the job, delete it afterwards, never log it, and record `keylog_attached` in custody. Decrypted content is never persisted. In this mode the "passive, nothing decrypted" claim does not hold, so state the mode on the capture.
- artifact_assisted evaluates the supplied chain with the same certificate engine. Findings from it carry confidence medium with basis "supplied by operator, not seen on the wire".

## 13. Fixtures required for every addition
Cover: a low-confidence finding with a basis; a TLS 1.3 session with certificate hidden; a partial capture; incidents in every state; a custody trail; an evaluation result containing at least one false positive and one false negative; an asset with pqc null; a capture analysed in key_assisted mode.