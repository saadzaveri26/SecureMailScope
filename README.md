# SecureMailScope

AI-assisted **passive cryptographic security-posture assessment for SMTP / IMAP / POP3** from PCAP files
(NTRO problem statement #26159). Backend: Python 3.10+, FastAPI. Dashboard (Next.js) consumes the REST API.

```
SecureMailScope/
├── .agents/                  AI-agent context: AGENTS.md, agents.yaml, workflows/
├── app_build/                The backend source (FastAPI app, tools, tests)
├── production_artifacts/     Runtime output: uploads, analyses, baselines, ML models, reports, trust store, sample PCAPs
├── NOVELTY_README.md         What is new beyond the problem statement
└── README.md
```

## Quick start
```bash
cd app_build
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python tools/generate_sample_pcaps.py                   # demo captures + enterprise CA into production_artifacts/
python run.py                                           # http://localhost:8000/docs
```
Demo flow: upload `securemail_baseline.pcap` with `create_baseline=true`, then upload `securemail_drift.pcap`
(baseline comparison is on by default) and open the dashboard/report. See `app_build/README.md` for the API.

Tests: `cd app_build && pytest -q` (19 tests, isolated temp artifacts dir).
