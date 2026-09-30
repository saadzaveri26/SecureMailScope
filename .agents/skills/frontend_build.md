# Skill: frontend_build

## Purpose
Build the analyst UI in Next.js (App Router, TypeScript) and Tailwind against production_artifacts/API_Contract.md, using fixtures until the backend is ready.

## Surfaces
1. Captures: drag-and-drop upload with size and type hints (advisory only), list with status, posture score and date. Processing shows progress by polling with backoff. Failed shows the reason and a retry.
2. Overview: posture score with a visible factor breakdown, counts by severity, protocol breakdown, transport breakdown (implicit TLS, STARTTLS, plaintext), the top prioritized findings. A trend line of posture score across captures.
3. Sessions explorer: dense, filterable, paginated table (protocol, client to server, transport, TLS version, cipher, forward secrecy, certificate status, findings). Row opens session detail.
4. Session detail: handshake steps in order, certificate chain viewer (subject, issuer, validity, days to expiry, key, signature, fingerprint), evidence panel with frame numbers and a copyable Wireshark filter. TLS 1.3 sessions show "Certificate not observable: TLS 1.3 encrypts it".
5. Findings: prioritized list with severity, category, evidence link, remediation steps with copyable snippets.
6. Drift: choose a baseline and a current capture, see before and after per endpoint with improved, degraded, changed.
7. Reports: buttons for JSON, HTML, PDF.
8. Landing page: optional, last.

## Rules
- Never call an endpoint or read a field that is not in the contract. If something is missing, propose a contract change instead.
- Fixtures first: NEXT_PUBLIC_USE_FIXTURES=1 serves them. Switch to the live API only at the integration step.
- Every list has loading, empty, error-with-retry and "not observable" states. Not observable is a neutral state, distinct from safe.
- Render captured strings as text only, truncate long values with a tooltip, and keep large tables paginated.
- Severity is never conveyed by color alone: color plus icon plus label.
- One chart library, three charts at most.
- Run the forensics_ui_principles checklist and the full-output-enforcement check before marking a surface done.
