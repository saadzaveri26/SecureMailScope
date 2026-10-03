# SecureMailScope 🛡️📧

> **AI-Assisted Passive Cryptographic Security Posture Assessment for Email Protocols (SMTP, IMAP, POP3)**  
> *Developed for NTRO Problem Statement #26159*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16.3-black.svg)](https://nextjs.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-38B2AC.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Overview

**SecureMailScope** is an enterprise-grade forensic security platform designed for **100% passive cryptographic inspection** of mail network traffic. Rather than actively scanning or probing mail servers (which can alert adversaries or disrupt critical infrastructure), SecureMailScope ingests raw packet captures (`.pcap`, `.pcapng`), reconstructs full bidirectional TCP mail streams, and evaluates cryptographic configurations across both the **Transport Layer** (TLS/STARTTLS) and the **Message Layer** (PGP, S/MIME).

### 🚀 Key Technical Innovations

1. **Cryptographic Baseline & Drift Detection Engine *(Headline Novelty)***:
   - While existing tools (Wireshark, tshark, testssl.sh) only report single-point-in-time weaknesses, SecureMailScope answers: *"What changed, on which mail server, in how many sessions, why does it matter, and what is the remediation?"*
   - Compares production traffic against certified baseline captures, calculating **Jensen-Shannon divergence** across TLS versions, ciphers, key exchanges, and certificate validity.
   - Distinguishes routine certificate renewals from unscheduled replacements, rogue CAs, cipher rollbacks, and active STARTTLS stripping.
2. **Baseline-Trained Isolation Forest ML Anomaly Detection**:
   - Trains an endpoint-specific Isolation Forest model on known-good baseline traffic across **29 cryptographic and behavioral features**.
   - **Explainable by Design**: Flags anomalies only when the mathematical score is high **and** at least one concrete human-readable reason can be stated (e.g., *"Negotiated TLS version = TLS 1.1, seen in 0.0% of reference sessions"*), eliminating false positives from network jitter.
   - The ML model can only *elevate* risk, ensuring deterministic security rules remain authoritative.
3. **Unified Transport + Message-Layer Posture**:
   - Inspects OpenPGP (ASCII armor, PKESK public-key algorithms, and detects symmetrically encrypted data lacking MDC to prevent **EFAIL** ciphertext-injection attacks).
   - Inspects S/MIME (PKCS#7 envelope dissection, weak `micalg` detection, and signer X.509 certificate extraction from the wire).
   - Identifies layer correlation risks (e.g., encrypted message bodies sent over cleartext transport, exposing sender/recipient metadata).
4. **Pure-Python Passive Dissector**:
   - Built on `dpkt` with a custom stream reassembly engine.
   - **Zero dependency on external binaries** like `tshark` or `tcpdump`.
   - Robustly handles TCP sequence number wrap-around, retransmitted packets, out-of-order delivery, VLAN tags, and Linux Cooked Mode (SLL) frames.
5. **Forensic Soundness & Chain of Custody**:
   - SHA-256 hashing of PCAP files upon upload.
   - Full analyst audit log tracking user identity, parser version, ruleset version, and timestamps.
   - Direct evidence linking: every finding cites the exact Wireshark display filter (`tcp.stream eq X`), frame numbers, and extracted byte snippets.

---

## 🏛️ System Architecture

```
                               ┌─────────────────────────┐
                               │   Raw PCAP / PCAPNG     │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │  Pure-Python Dissector  │
                               │  (dpkt + TCP Reassembly)│
                               └────────────┬────────────┘
                                            │
                                            ▼
                           ┌─────────────────────────────────┐
                           │   Stream Classification & DPI   │
                           ├────────────────┬────────────────┤
                           │  SMTP Dialog   │  IMAP / POP3   │
                           │  STARTTLS / S  │  Cleartext     │
                           └────────┬───────┴────────┬───────┘
                                    │                │
            ┌───────────────────────┴────────┐       │
            ▼                                ▼       ▼
┌───────────────────────┐        ┌─────────────────────────┐
│  TLS Record Dissector │        │  Message Layer Scanner  │
│  (Handshake, Ciphers, │        │  (OpenPGP, S/MIME,      │
│   PQC, X.509 Chains)  │        │   EFAIL MDC Detection)  │
└───────────┬───────────┘        └───────────┬─────────────┘
            │                                │
            └────────────────┬───────────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │    44 Security Rules      │
               │   + Isolation Forest ML   │
               └─────────────┬─────────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
┌───────────────────────────┐     ┌───────────────────────────┐
│ Posture Scoring (0 - 100) │     │ Drift Engine vs Baseline  │
│ Grade: A / B / C / D / F  │     │ (JS-Divergence, Cert/KEX) │
└───────────┬───────────────┘     └───────────┬───────────────┘
            │                                 │
            └────────────────┬────────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │  FastAPI REST Service (8000)│
              └──────────────┬──────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │ Next.js 16 Dashboard (3001) │
              │ (Overview, Sessions, Drift) │
              └─────────────────────────────┘
```

---

## 📊 Posture Scoring Rubrics & Grade Scale

The posture score is computed on a scale from **0 to 100**:

$$\text{Posture Score} = 100 - \sum (\text{Impact Penalty} \times \text{Exposure Ratio})$$

### Letter Grade Rubric

| Grade | Score Range | Status | Definition |
|:---:|:---:|:---:|---|
| **A** | **90 – 100** | **Excellent** | Modern TLS 1.2/1.3, strong AEAD ciphers, Perfect Forward Secrecy (PFS), valid certificate chains, no cleartext exposure. |
| **B** | **80 – 89** | **Good** | Strong security baseline; minor configuration optimizations or legacy ciphers enabled for compatibility. |
| **C** | **65 – 79** | **Fair** | Outdated ciphers (CBC mode), expiring certificates, or absence of Post-Quantum hybrid protection. |
| **D** | **50 – 64** | **Poor** | Deprecated protocols (TLS 1.0/1.1), self-signed certificates, missing Forward Secrecy, or weak key sizes (<2048-bit RSA). |
| **F** | **< 50** | **Critical** | Cleartext credentials exposed, unencrypted sessions on submission ports, or active STARTTLS stripping observed. |

### The 5 Core Factor Dimensions

1. **Transport Security (35% weight)**: Cleartext credential leaks, unencrypted sessions, refused STARTTLS, command injection.
2. **Certificate Hygiene (25% weight)**: Expired certs, self-signed certs, weak signature hashes (SHA-1/MD5), RSA keys < 2048 bits.
3. **Protocol Configuration (20% weight)**: Negotiated SSLv3/TLS 1.0/TLS 1.1, downgrade sentinels, insecure renegotiation, CRIME compression.
4. **Cipher Strength (15% weight)**: RC4, 3DES, EXPORT, NULL ciphers, non-PFS key exchanges, Logjam weak DHE groups.
5. **Message Layer (5% weight)**: OpenPGP without MDC protection (EFAIL vulnerability), weak S/MIME hash algorithms.

---

## 🗂️ Project Structure

```
SecureMailScope/
├── app_build/                       # Backend service & analysis engine
│   ├── app/
│   │   ├── analysis/                # Core analysis pipelines & rules
│   │   │   ├── pipeline.py          # End-to-end packet processing pipeline
│   │   │   ├── rules.py             # Rule evaluation & aggregation
│   │   │   ├── rule_catalog.py      # Catalog of 44 deterministic rules
│   │   │   ├── risk_engine.py       # Posture & session risk computation
│   │   │   ├── drift.py             # Cryptographic drift detection engine
│   │   │   ├── baseline.py          # Baseline profiling & serialization
│   │   │   └── ml_anomaly.py        # 29-feature Isolation Forest ML model
│   │   ├── api/                     # FastAPI route handlers & dependencies
│   │   │   ├── contract_02.py       # REST API contract endpoints
│   │   │   └── deps.py              # Authentication & authorization guards
│   │   ├── core/                    # Low-level protocol dissectors
│   │   │   ├── pcap_reader.py       # dpkt PCAP & PCAPNG parser
│   │   │   ├── tcp_reassembly.py    # Bidirectional TCP stream reassembly
│   │   │   ├── tls_parser.py        # TLS handshake & record dissector
│   │   │   ├── cert_analyzer.py     # X.509 certificate chain analyzer
│   │   │   └── message_security.py  # OpenPGP & S/MIME payload scanner
│   │   └── config.py                # Central application configuration
│   ├── frontend/                    # Next.js 16 Analyst Dashboard
│   │   ├── src/
│   │   │   ├── app/                 # Next.js App Router (7 Core Views)
│   │   │   │   ├── captures/        # Upload & PCAP ingestion view
│   │   │   │   ├── overview/        # Executive posture score & factor cards
│   │   │   │   ├── sessions/        # Interactive session inspector
│   │   │   │   ├── findings/        # Prioritized findings & remediation
│   │   │   │   ├── drift/           # Baseline comparison & diff viewer
│   │   │   │   ├── evaluation/      # Precision, recall, and benchmark tests
│   │   │   │   └── reports/         # PDF, HTML, JSON report exporter
│   │   │   ├── components/          # Reusable forensic UI components
│   │   │   └── data.ts              # Resilient API communication layer
│   │   └── demo-data/               # Pre-exported ground-truth models
│   ├── requirements.txt             # Python dependencies
│   └── run.py                       # FastAPI entrypoint
├── demo_captures/                   # Ground-truth PCAP laboratory captures
│   ├── securemail_baseline.pcap     # Certified healthy baseline (Score 100, A)
│   ├── securemail_drift.pcap        # Regressed operational capture (Score 40, F)
│   └── manifest.json                # Capture definitions & expected findings
├── production_artifacts/            # Generated reports, baselines, and models
├── scripts/                         # Snapshot export & CLI utilities
├── NOVELTY_README.md                # Detailed list of features beyond NTRO #26159
└── README.md
```

---

## ⚡ Quick Start

### 1. Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18.x or higher
- **Git**

### 2. Backend Setup (FastAPI)
```bash
# Clone the repository
git clone https://github.com/saadzaveri26/SecureMailScope.git
cd SecureMailScope/app_build

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the backend server (runs on http://localhost:8000)
python run.py
```

### 3. Frontend Setup (Next.js)
In a new terminal:
```bash
cd SecureMailScope/app_build/frontend

# Install dependencies
npm install

# Start the development server (runs on http://localhost:3001)
npm run dev
```

Open your browser at `http://localhost:3001`.

### 4. Access Credentials
When prompted in the analyst portal:
- **Access Token**: `sms-analyst-token` *(or any token string when running locally)*
- **Analyst Name**: `analyst` *(or your username/handle)*

---

## 🧪 Ground-Truth Test Captures

SecureMailScope includes verified lab captures in `demo_captures/`:

1. **`securemail_baseline.pcap`**:
   - Represents a certified, secure enterprise email infrastructure.
   - **Score**: **100 (Grade A)**
   - 3,457 packets across 177 sessions.
   - Valid TLS 1.2/1.3, modern AEAD cipher suites, clean certificate chains, no cleartext auth.
2. **`securemail_drift.pcap`**:
   - Represents an environment suffering from configuration drift and attacks.
   - **Score**: **40 (Grade F)**
   - 3,103 packets across 167 sessions.
   - Contains: STARTTLS stripping, TLS 1.0/1.1 rollbacks, cleartext IMAP logins, expired certificates, and legacy CBC ciphers.

---

## 🔍 Interactive UI Views

1. **Captures (`/captures`)**: Upload new PCAP/PCAPNG captures and monitor processing status.
2. **Overview (`/overview`)**: Posture score gauge, 5-factor impact breakdown, severity distribution, and visibility limitations.
3. **Sessions (`/sessions`)**: Filter and inspect individual TCP streams. Each session provides an **Explainability Card** detailing exact handshake negotiation, TLS parameters, and certificate validation.
4. **Findings (`/findings`)**: Ranked list of all rule violations with direct copy-paste configuration snippets for **Postfix**, **Dovecot**, and **Exim**.
5. **Drift (`/drift`)**: Visual comparison against the baseline showing protocol regressions, cipher rollbacks, and rogue MTAs.
6. **Evaluation (`/evaluation`)**: Benchmarking dashboard displaying precision, recall, and detection accuracy.
7. **Reports (`/reports`)**: One-click export to comprehensive **PDF**, **HTML**, and **JSON** reports with cryptographic chain-of-custody hashes.

---

## 🛡️ Responsible Disclosure & Limitations

- **Passive Analysis Limitation**: Encrypted application traffic (TLS 1.3 or session payloads) cannot be decrypted without external key material. Certificate chain evaluation for TLS 1.3 relies on observable SNI and negotiation metadata.
- **Privacy & Safety**: Usernames captured in cleartext authentication dialogs are recorded for forensic evidence, while passwords are automatically masked before serialization.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
