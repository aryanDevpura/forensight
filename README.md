# ForenSight — Digital Evidence Collection & Forensic Analysis System

ForenSight is a digital evidence collection, integrity verification, and forensic analysis system designed for academic evaluation, security investigations, and incident response workflows.

---

## Architecture Overview

The system is organized into two primary logical components:

1. **Forensic Investigation Server (`server/`)**:
   - Central investigation backend built on **FastAPI** and **SQLAlchemy 2.0**.
   - Storage layer powered by local filesystem directories (`./storage/evidence` and `./storage/reports`) and an embedded **SQLite** database (`forensight.db`).
   - REST/JSON communication interface providing endpoints for health probes, system status, evidence registry, and future forensic analytics.

2. **Evidence Collector (`collector/`)**:
   - Lightweight client module designed to run on the investigation workstation or remote host/virtual machine.
   - Configurable target server host and port (`COLLECTOR_SERVER_HOST`, `COLLECTOR_SERVER_PORT`), enabling remote networked collection in future milestones.

3. **Investigation Dashboard (`client/`)**:
   - Desktop-grade web interface built with **React**, **Vite**, and **Tailwind CSS**.
   - Information-first design featuring real system telemetry, database status, module readiness, and empty state representations without synthetic/mock evidence.

---

## Project Structure

```
forensight/
├── client/                     # React + Vite + Tailwind CSS Frontend
│   ├── src/
│   │   ├── api/                # REST client for backend communication
│   │   ├── components/         # Layout (Sidebar, Header) and reusable UI widgets
│   │   ├── pages/              # Module views (Dashboard, Evidence, Analysis, Timeline, etc.)
│   │   ├── App.jsx             # Shell & state coordinator
│   │   └── main.jsx            # React root mount
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
├── server/                     # FastAPI Backend Server
│   ├── app/
│   │   ├── api/
│   │   │   ├── endpoints/      # Health check, system stats, schema models
│   │   │   └── routes.py       # API route registry
│   │   ├── core/               # Configuration settings (pydantic-settings)
│   │   ├── database/           # SQLite engine, sessions, schema initialization
│   │   ├── models/             # SQLAlchemy ORM models (Evidence, Custody, Findings, etc.)
│   │   ├── services/           # Service layer for upcoming forensic engines
│   │   └── main.py             # FastAPI application entry point
│   ├── storage/
│   │   ├── evidence/           # Local evidence artifact storage
│   │   └── reports/            # Generated forensic investigation reports
│   └── requirements.txt        # Python backend dependencies
├── collector/                  # Evidence Collector Node Module
│   ├── collector.py            # EvidenceCollector client class & server probe
│   ├── config.py               # Configurable host, port, and collector identity
│   └── main.py                 # Standalone collector CLI test runner
├── tests/                      # Automated test suite (pytest)
│   ├── test_health.py          # API and database tests
│   └── test_collector_config.py# Collector configuration tests
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

# Create .env from template (if not already present)
cp .env.example .env
```

### 2. Start the Backend Server

```bash
# Run FastAPI server with Uvicorn
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

Interactive API documentation is available at: `http://127.0.0.1:8000/docs`

### 3. Frontend Setup & Launch

From the repository root:

```bash
cd client
npm install
npm run dev
```

The interface will be accessible at: `http://localhost:5173`

### 4. Collector Health Probe

Test the Evidence Collector's remote connection to the server:

```bash
python -m collector.main
```

Output:
```
============================================================
 ForenSight — Digital Evidence Collector
============================================================
 Collector ID        : collector-node-01
 Target Server Host  : 127.0.0.1
 Target Server Port  : 8000
 Health Check URL    : http://127.0.0.1:8000/api/health
------------------------------------------------------------
Checking connection to ForenSight Investigation Server...
[SUCCESS] Connected to ForenSight Server!
```

### 5. Running Tests

Run the test suite with `pytest`:

```bash
pytest -v tests
```

---

## Roadmap & Upcoming Milestones

- **Milestone 2: Evidence Ingestion & Cryptographic Integrity**
  - SHA-256 chunked hashing & baseline hash verification
  - HMAC-SHA256 authenticated transmission & nonce-based replay protection
  - Automated Chain of Custody entry generation
- **Milestone 3: Deep Packet Inspection & Threat Detection**
  - PyShark PCAP dissector
  - Scan detection heuristics & beaconing pattern analysis
  - USB device event timeline reconstruction
- **Milestone 4: Reporting & Performance Benchmarking**
  - Court-admissible forensic summary export (PDF/JSON)
  - Standardized benchmarking harness (MB/s throughput & latency metrics)
