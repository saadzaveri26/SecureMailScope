# Skill: audit_code

Report PASS or a list of issues with file and line. Do not fix.

## Checklist
1. Contract: every endpoint, field, enum and nullability matches production_artifacts/API_Contract.md on both sides.
2. Untrusted input: magic-byte check, size cap enforced while streaming, UUID storage names, no shell=True, subprocess timeout and bounded output, non-root container, temp files cleaned up.
3. Privacy: no payloads, bodies or credentials persisted or logged. Cleartext auth appears only as a finding. Retention deletion works.
4. Output escaping: captured strings are escaped in the HTML report and rendered as text in the UI. No dangerouslySetInnerHTML.
5. Honesty: null shows as "not observable", never as safe. TLS 1.3 certificate case handled. Message-layer "not observable" is not reported as "absent". Anomalies are worded as deviations. No claim of decryption anywhere.
6. Determinism: ML never changes a rule-based severity. Every anomaly explains itself. The insufficient-baseline path exists.
7. Verification: the manifest test runs and the results are shown. The clean capture has no critical or high findings.
8. Hygiene: secrets from environment only, strict CORS, generic 500 responses, rate limits, no dead code or placeholders.
9. Completeness: run the full-output-enforcement check on the touched files.
