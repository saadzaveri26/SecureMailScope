# Workflow: startcycle

## Steps for every feature
1. Contract Agent: confirm the feature is covered by production_artifacts/API_Contract.md. If not, add it there first (bump the version, add a Changelog line) and tell the other side.
2. Owning agent implements using its skill. Backend proves behaviour on the ground-truth captures; frontend proves it on fixtures.
3. Code Auditor Agent runs audit_code. Any FAIL goes back to step 2 with the exact issue.
4. Stop and report. Do not start the next pass without confirmation.

## Build order
1. Contract and fixtures (first hour, both sides together).
2. Backend: lab captures and manifest, upload, tshark extraction, sessions with protocol/STARTTLS/TLS fields. Frontend: scaffold, tokens, upload and overview pages on fixtures.
3. Backend: certificates, rules, posture score, prioritization, remediation. Frontend: sessions explorer, session detail, findings.
4. Backend: anomaly detection and drift. Frontend: drift view.
5. Backend: reports (JSON, HTML, PDF). Frontend: export and polish states.
6. Backend: PGP/S-MIME detection. This is the first thing to cut if time runs out.
7. Integration: switch the frontend from fixtures to the live backend and run the manifest checks end to end.
8. Optional landing page.

## Ground rules
- Passive analysis only. Never decrypt, never claim to decrypt.
- null means not observable. It is never displayed or scored as safe.
- Deterministic rules set severity. ML only adds separate, explained anomaly findings.
- PCAP contents are untrusted and private: no payload or credential persistence, all captured strings escaped on output.
- Rules and remediation live in data files, not inline code.
- No silent fallbacks: a missing tshark fails startup loudly.
- Every "done" claim comes with command output or a screenshot.

## Current state
Fresh repository. Nothing built.
