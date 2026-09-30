# app_build - SecureMailScope backend

## Pipeline
```
PCAP/PCAPNG -> pcap_reader (dpkt) -> tcp_reassembly (flows, retransmit/reorder) -> protocol_detector (SMTP/IMAP/POP3, mode)
  -> mail_dialog (STARTTLS, auth, capabilities) + tls_parser (records, handshakes, JA3) + cert_analyzer (X.509, chain, trust)
  + message_security (PGP / S-MIME)  => session records
  -> rules (44 rules) -> ml_anomaly (Isolation Forest) -> risk_engine (session risk, posture, explanations)
  -> baseline / drift -> prioritisation + remediation plan -> storage -> reports (JSON/HTML/PDF) -> REST API / dashboard
```

## Layout
| Path | Purpose |
|---|---|
| `app/config.py` | Paths (-> `../production_artifacts`), ports, thresholds |
| `app/core/` | Passive protocol engine: `pcap_reader`, `tcp_reassembly`, `protocol_detector`, `mail_dialog`, `tls_parser`, `cipher_db`, `cert_analyzer`, `message_security`, `session_builder` |
| `app/analysis/` | `rule_catalog`, `rules`, `ml_anomaly`, `risk_engine`, `baseline`, `drift`, `pipeline`, `common` |
| `app/reports/` | `json_report`, `html_report`, `pdf_report` (ReportLab), `common` |
| `app/api/` | Routers: `analyses`, `baselines`, `dashboard`, `reports`, `meta`, `deps` (optional API key) |
| `app/storage.py`, `app/jobs.py` | File persistence (atomic writes) and async job registry |
| `tools/generate_sample_pcaps.py` | Synthetic baseline/drift captures |
| `tests/` | pytest suite |

## REST API (prefix `/api/v1`, docs at `/docs`)
| Method & path | Purpose |
|---|---|
| `POST /analyses` | multipart `files[]` (single or batch), form: `compare_baseline`(true) `create_baseline`(false) `wait`(true) `analyst` |
| `GET /analyses/jobs/{job_id}` | status when `wait=false` |
| `GET /analyses`, `GET/DELETE /analyses/{id}` | list / full result (`include_sessions=true` for sessions) |
| `GET /analyses/{id}/sessions` | filters: `protocol endpoint transport tls_version risk_level min_risk anomalous sort offset limit` |
| `GET /analyses/{id}/sessions/{sid}` | full session + **explainable assessment card** |
| `GET /analyses/{id}/findings` | prioritised; `severity category endpoint include_info` |
| `GET /analyses/{id}/posture · anomalies · certificates · drift · message-security` | sections |
| `POST /analyses/{id}/drift/recompute` | re-compare against current baselines |
| `GET/POST /baselines`, `GET/DELETE /baselines/{endpoint}`, `GET /baselines/{endpoint}/history` | baseline management |
| `GET /analyses/{id}/report?format=json\|html\|pdf`, `POST /analyses/{id}/reports`, `GET /reports` | reports |
| `GET /dashboard/overview`, `GET /dashboard/trend?endpoint=` | dashboard data (severity, protocol, trend, top findings, drift, cert expiry) |
| `GET /meta/rules · cipher-suites · trust-store`, `POST /meta/trust-store/reload` | catalogues |
| `GET /health` | liveness |

## Configuration (env)
`SMS_ARTIFACTS_DIR`, `SMS_MAX_UPLOAD_MB` (512), `SMS_API_KEY` (if set, send `X-API-Key`), `SMS_CORS_ORIGINS` (Next.js dev origins), `SMS_HOST`, `SMS_PORT`.

## Using your own captures
Capture with `tcpdump -i any -w mail.pcap 'port 25 or 465 or 587 or 110 or 143 or 993 or 995'` while a client talks to your
server (Postfix/Dovecot/Exim). Put private CA roots in `production_artifacts/trust_store/` then `POST /meta/trust-store/reload`.

## Design notes
* Endpoint identity = `server_ip:port`; hostname (SNI/certificate) is display metadata.
* Posture score = 100 - sum(severity points x (0.5 + 0.5 x exposure)); INFO and drift findings do not reduce it.
* Session risk = `1-prod(1-w_sev)`, combined with ML as `1-(1-rule)(1-0.5*ml)`.
* Dashboard `trend` is ordered by **capture time** (not upload time).
