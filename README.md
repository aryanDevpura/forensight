# ForenSight — Digital Evidence Collection & Forensic Analysis System

ForenSight is a digital evidence collection, cryptographic integrity verification, forensic timeline correlation, and analysis system designed for academic evaluation, incident response investigations, and auditable evidence management.

---

## Architecture Overview

The system is organized into three primary logical tiers:

1. **Forensic Investigation Server (`server/`)**:
   - Central investigation backend built with **FastAPI** and **SQLAlchemy 2.0**.
   - Storage layer powered by local filesystem directories (`./storage/evidence` and `./storage/reports`) and an embedded **SQLite** database (`forensight.db`).
   - Secure evidence ingestion engine with streaming SHA-256 calculation, HMAC-SHA256 request authentication, and AES-256-GCM transfer decryption.
   - Forensic analysis engine for PCAP network packet dissection, threat heuristic inspection (e.g. port scans, cleartext protocol detection), chronological forensic timeline generation, and chain-of-custody tracking.
   - High-resolution monotonic benchmark recorder auditing hashing, ingestion, HMAC verification, decryption, and analysis latencies.

2. **Evidence Collector & Reusable Utilities (`collector/`)**:
   - Edge collection utilities designed to run on investigation workstations or remote endpoints/VMs.
   - Computes original evidence SHA-256 digests (`compute_payload_hash`).
   - Implements **AES-256-GCM authenticated encryption** with unique 12-byte random nonces and context binding.
   - Reusable HMAC-SHA256 signature and metrics helpers (`sign_request_with_metrics`).

3. **Investigation Dashboard (`client/`)**:
   - Desktop-grade web interface built with **React**, **Vite**, and **Tailwind CSS**.
   - Full Web Crypto API client-side cryptography pipeline (SHA-256 hashing, AES-256-GCM symmetric encryption, RSA-OAEP key wrapping, and RSA-PSS digital signing).
   - Information-first design featuring real system telemetry, database status, module readiness, and empty state representations without synthetic/mock evidence.
   - Interactive pages for Evidence Management, PCAP Analysis, Chain of Custody Ledger, Forensic Timeline Exploration, Performance Telemetry Dashboard, and System Configuration.

---

## Core Security & Forensic Features

- **Unified Secure Evidence Ingestion (`POST /api/evidence`)**:
  - Sole supported evidence ingestion path. All uploads are encrypted before leaving the browser.
  - **SHA-256 Original Integrity**: Plaintext hash calculated over original bytes prior to encryption and verified server-side after decryption.
  - **AES-256-GCM Payload Encryption**: Fresh 256-bit symmetric key per artifact; unique 96-bit nonce; 128-bit authentication tag.
  - **RSA-OAEP Key Wrapping**: AES key encrypted under server's RSA public key (2048-bit, SHA-256, MGF1).
  - **RSA-PSS Digital Signature**: Canonical JSON metadata claims signed using client's RSA private key and verified against server's trusted signer registry.
  - **Preserved Custody & Storage**: At-rest encrypted artifact persistence with full ACQUIRED chain-of-custody recording.
  - **Authorized Download**: Verified on-the-fly decryption with authentication tag check and SHA-256 validation.
- **Cryptographic Chain of Custody**:
  - Immutable audit trail recording evidence lifecycle actions (`ACQUIRED`, `ANALYZED`, etc.), actors, storage paths, and SHA-256 integrity notes.
- **Forensic Timeline & Correlation**:
  - Automatic extraction of chronological network flow events and security findings from PCAP artifacts.
- **Auditable Performance Telemetry**:
  - Microsecond-accurate monotonic timer instrumentation recording actual runtime duration (ms) and throughput (MB/s) for hashing, ingestion, HMAC verification, AES decryption, and packet analysis.

---

## Project Structure

```
forensight/
├── client/                     # React + Vite + Tailwind CSS Frontend
│   ├── src/
│   │   ├── api/                # REST client for backend communication
│   │   ├── components/         # Layout (Sidebar, Header) and reusable UI widgets
│   │   ├── pages/              # Dashboard, Evidence, Analysis, Custody, Timeline, Performance, Settings
│   │   ├── App.jsx             # Shell & view router coordinator
│   │   └── main.jsx            # React root mount
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
├── server/                     # FastAPI Backend Server
│   ├── app/
│   │   ├── api/
│   │   │   ├── endpoints/      # Health, system stats, evidence, analysis, custody, timeline, benchmarks
│   │   │   └── routes.py       # API route registry
│   │   ├── core/               # Configuration settings, HMAC auth, AES-GCM crypto, benchmark recorder
│   │   ├── database/           # SQLite engine, sessions, schema initialization
│   │   ├── models/             # Evidence, ChainOfCustody, Finding, InvestigationEvent, BenchmarkResult
│   │   ├── services/           # PCAP analyzer and forensic heuristics
│   │   └── main.py             # FastAPI application entry point
│   ├── storage/
│   │   ├── evidence/           # Local evidence artifact storage
│   │   └── reports/            # Generated forensic investigation reports
│   └── requirements.txt        # Python backend dependencies
├── collector/                  # Evidence Collector Node Module
│   ├── auth.py                 # HMAC-SHA256 request signing & hashing
│   ├── collector.py            # EvidenceCollector client class & authenticated upload flow
│   ├── config.py               # Collector settings, endpoints, and credentials
│   ├── crypto.py               # AES-256-GCM authenticated transfer encryption
│   └── main.py                 # Standalone collector CLI test runner
├── tests/                      # Automated test suite (pytest - 56 test cases)
│   ├── test_analysis.py        # PCAP dissection, heuristics, and findings tests
│   ├── test_benchmarks.py      # Runtime benchmark instrumentation tests
│   ├── test_collector_config.py# Collector config default tests
│   ├── test_custody.py         # Chain of custody lifecycle tests
│   ├── test_encryption.py      # AES-256-GCM transfer encryption and error handling tests
│   ├── test_evidence.py        # Evidence upload, SHA-256 hashing, path traversal tests
│   ├── test_health.py          # API and system stats tests
│   ├── test_hmac_auth.py       # HMAC authentication and replay protection tests
│   └── test_timeline.py        # Forensic timeline generation tests
├── .env.example                # Environment variables template
├── .gitignore                  # Git ignore rules
└── README.md                   # System documentation
```

---

## Getting Started

### Prerequisites
- Python 3.10+ (tested with Python 3.12)
- Node.js 18+ and npm

### 1. Backend Setup

From the repository root:

```bash
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate   # Windows PowerShell
# source .venv/bin/activate # Linux / macOS

# Install backend dependencies
pip install -r server/requirements.txt

# Configure environment variables (if .env is not present)
cp .env.example .env
```

Ensure `.env` contains secure pre-shared keys:
```env
FORENSIGHT_HMAC_SECRET=forensight-dev-hmac-secret-change-in-production-7f3a9b2e
FORENSIGHT_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### 2. Start the Backend Server

```bash
uvicorn server.app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify backend health:
```bash
curl http://127.0.0.1:8000/api/health
```

Expected response:
```json
{
  "status": "ok",
  "app": "ForenSight Investigation Server",
  "version": "0.1.0",
  "environment": "development",
  "database": "connected",
  "storage": {
    "evidence_dir": "available",
    "reports_dir": "available"
  }
}
```

Interactive OpenAPI documentation is available at: `http://127.0.0.1:8000/docs`

### 3. Frontend Setup & Launch

From the repository root:

```bash
cd client
npm install
npm run dev
```

The web dashboard is accessible at: `http://localhost:5173`

### 4. Collector Health Probe & Evidence Upload

Probe server connectivity from the collector:

```bash
python -m collector.main
```

Programmatic authenticated evidence upload with encryption:
```python
from collector import EvidenceCollector, CollectorConfig

config = CollectorConfig()
collector = EvidenceCollector(config)
success, details = collector.upload_evidence_authenticated("sample.pcap", source_device="sensor-01")
print(success, details)
```

### 5. Running Automated Tests

Run the full pytest suite:

```bash
python -m pytest tests/ -v --tb=short
```

Run frontend build verification:
```bash
cd client
npm run build
```

---

## API Summary

| Endpoint | Method | Description | Auth Required |
|---|---|---|---|
| `/api/health` | GET | Server health, database status, and storage availability | None |
| `/api/system/stats` | GET | Real database record counts and subsystem state | None |
| `/api/system/public-keys` | GET | Retrieve server RSA public key & demo signing credentials | None |
| `/api/evidence` | GET | List all registered forensic evidence records | None |
| `/api/evidence` | POST | Unified secure evidence upload (RSA-PSS + AES-GCM + SHA-256) | RSA-PSS Signature |
| `/api/evidence/{evidence_id}/download` | GET | Authorized evidence download (on-the-fly decryption & integrity check) | None |
| `/api/evidence/{evidence_id}/verify` | POST | Post-acquisition integrity verification against stored SHA-256 | None |
| `/api/custody/{evidence_id}` | GET | Retrieve chain-of-custody audit records | None |
| `/api/analysis/{evidence_id}` | POST | Execute PCAP analysis and heuristic detection | None |
| `/api/analysis/findings` | GET | Retrieve detected security and forensic findings | None |
| `/api/timeline/{evidence_id}` | GET | Chronological forensic event timeline | None |
| `/api/benchmarks` | GET | Retrieve recorded performance benchmarks | None |
| `/api/benchmarks/summary` | GET | Aggregate benchmark statistics and throughput | None |
| `/api/benchmarks/evidence/{evidence_id}` | GET | Benchmarks associated with specific evidence | None |
  