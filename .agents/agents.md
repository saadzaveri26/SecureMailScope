# SecureMailScope — Agent Roster

Two people build in parallel: one owns app_build/frontend (Next.js + Tailwind), one owns app_build/backend (FastAPI + tshark). The only shared surface is production_artifacts/API_Contract.md. Neither side calls or serves a field that is not in the contract.

Layout:
```
.agents/agents.md
.agents/skills/*.md
.agents/workflows/startcycle.md
app_build/backend/       FastAPI, tshark extraction, scoring, reports
app_build/frontend/      Next.js, Tailwind, fixtures/
production_artifacts/API_Contract.md
```

Taste-skill folders live wherever the installer put them (.agents/.skills/.agents/skills/<name>/). Reference them by full path; see tasteskill_integration.md.

## Shared
- Contract Agent: keeps API_Contract.md and the fixtures consistent. Uses api_contract.
- Code Auditor Agent: reviews finished work. Uses audit_code. Reports only, never fixes.

## Backend
- Ingestion Agent: upload, validation, tshark execution, job status. Uses pcap_ingestion.
- Analysis Agent: protocol and STARTTLS detection, TLS parsing, certificates, weak-crypto rules. Uses protocol_tls_analysis.
- Scoring Agent: posture score, prioritization, anomaly detection, drift. Uses risk_scoring and anomaly_drift.
- Message Security Agent: PGP/OpenPGP and S/MIME detection. Uses pgp_smime_detection.
- Reporting Agent: remediation data, JSON/HTML/PDF reports, evidence links. Uses remediation_reports.
- Test Data Agent: lab servers, ground-truth captures, manifest. Uses demo_captures.

## Frontend
- Frontend Agent: pages and components against contract fixtures. Uses frontend_build.
- Design Agent: visual direction for every analyst surface. Uses forensics_ui_principles.
- Landing Design Agent: the optional landing page only. Uses tasteskill_integration.
