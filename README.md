# PasswordlessAuth - SecureBank Academic Demo

A full-stack academic security demo that showcases passwordless authentication with device-bound private keys, nonce-based challenge-response, contextual risk scoring, step-up authentication, and tamper-evident audit logging.

This project is designed for security experimentation, performance benchmarking, and attack simulation in a controlled local environment.

## Table of Contents

- Project Overview
- Core Security Design
- Key Features
- Unique Contributions
- Tech Stack
- Architecture
- Folder Structure
- Local Development Guide
- API Overview
- Metrics and Benchmarking
- Attack Simulation
- Troubleshooting
- Contributors
- License
- Current Limitations
- Roadmap Ideas

## Project Overview

PasswordlessAuth replaces static passwords with an asymmetric cryptography flow:

1. A browser-generated RSA key pair is created at registration.
2. The private key is encrypted client-side with an AES key derived from device fingerprint material using PBKDF2.
3. During login and sensitive operations, the server issues short-lived nonces.
4. The browser decrypts and uses the private key in-memory to sign those nonces.
5. The server verifies signatures against stored public keys and evaluates contextual risk.
6. Medium/high risk actions trigger TOTP step-up or DENY.
7. Admin account workflows provide audit log visibility, hash-chain verification, and controlled tamper/restore checks.

The backend maintains an append-only hash-chained audit log and provides integrity verification routes for tamper detection experiments.

## Core Security Design

### Authentication and Key Management

- RSA-PSS signatures with SHA-256 for nonce signing.
- Client-side key generation via Web Crypto API.
- Encrypted private key bundle stored locally as ciphertext only.
- PBKDF2-SHA256 (310,000 iterations) for deriving AES-256-GCM master key from fingerprint + salt.
- Plain private key bytes are used in RAM temporarily and zeroed after use.

### Nonce and Replay Protection

- Login nonce issued by /challenge and consumed on use.
- Operation nonce issued by /operation-challenge with a 60-second validity window.
- Operation context hash binds nonce to action context.
- Reuse, mismatch, tampering, and expiry attempts are denied.

### Risk Engine and Step-Up

- Risk factors include operation type, amount, behavior signals, IP anomaly, session age, and velocity.
- Decision mapping:
  - ALLOW for low risk
  - STEP_UP for medium risk (TOTP)
  - DENY for high risk

### Audit Integrity

- Each audit log row stores prev_hash and current_hash.
- Verification endpoint detects tampering by chain mismatch.
- Admin tools support controlled tamper and restore demonstrations.

## Key Features

- Passwordless login using RSA challenge-response
- Device-bound encrypted private key storage
- Risk-aware operation authorization (ALLOW / STEP_UP / DENY)
- TOTP step-up authentication
- Tamper-evident audit logging with chain verification
- Frontend and backend performance instrumentation
- Automated benchmark scripts for FAR/FRR and risk metrics
- Attack simulation scripts for replay, forged signatures, tamper attempts
- Rich frontend demo views for security education and presentations

## Unique Contributions

- End-to-end browser-only private key protection with RAM-first handling
- Context-bound operation nonces (nonce + operation + context integrity)
- Security + usability + risk benchmarking in one workflow
- Educational observability through live security audit UI logs
- Integrated offensive testing and defensive metric reporting

## Tech Stack

### Frontend

- React 19
- TypeScript
- Vite 6
- Lucide React icons
- Web Crypto API

### Backend

- Python 3
- Flask
- Flask-CORS
- SQLite
- cryptography
- pyotp
- qrcode
- requests (benchmark scripts)

### Security Primitives

- RSA-PSS (SHA-256)
- AES-256-GCM
- PBKDF2-HMAC-SHA256
- SHA-256 hash chaining
- TOTP

## Architecture

### High-Level Flow

1. Register:
   - Browser generates RSA key pair.
   - Private key encrypted and stored locally.
   - Public key registered on backend.
2. Login:
   - Server issues nonce.
   - Browser decrypts key, signs nonce.
   - Server verifies signature and grants access.
3. Sensitive operation:
   - Browser sends context for operation challenge.
   - Server returns context-bound nonce.
   - Browser signs nonce and executes operation.
   - Server runs risk policy and returns ALLOW / STEP_UP / DENY.
4. Step-up:
   - User submits TOTP code.
   - Server verifies and upgrades decision if valid.
5. Logging:
   - Every relevant action is hash-chained in audit logs.

## Folder Structure

```text
PasswordlessAuth/
├── attack_demo.py
├── index.html
├── metadata.json
├── package.json
├── package-lock.json
├── tsconfig.json
├── vite.config.ts
├── README.md
├── src/
│   ├── App.tsx
│   ├── constants.tsx
│   ├── index.tsx
│   ├── types.ts
│   ├── components/
│   │   ├── AttackSimulator.tsx
│   │   ├── InfoTooltip.tsx
│   │   ├── RiskDebugger.tsx
│   │   ├── RiskMeter.tsx
│   │   └── SecurityAuditPanel.tsx
│   ├── pages/
│   │   ├── AdminDashboard.tsx
│   │   ├── AuditLogs.tsx
│   │   ├── Dashboard.tsx
│   │   ├── IntegrityCheck.tsx
│   │   ├── Login.tsx
│   │   ├── SecureOperation.tsx
│   │   ├── StepUp.tsx
│   │   └── Transfer.tsx
│   ├── services/
│   │   └── api.ts
│   └── utils/
│       ├── deviceKey.ts
│       ├── keygen.ts
│       └── riskEngine.ts
└── backend/
    ├── app.py
    ├── risk_policy.py
    ├── metrics_benchmark.py
    ├── aggregate_benchmarks.py
    ├── simulate_risk.py
    ├── calc_frontend_stats.py
    ├── securebank.db                 # generated local DB
    ├── metrics_run*.json             # generated benchmark outputs
    ├── aggregate_summary.json        # generated summary output
    ├── metrics_nonce_5.json          # generated nonce benchmark output
    ├── frontend_metrics_raw.txt      # optional local raw console capture
    └── venv/                         # optional local virtual environment
```

## Local Development Guide

### Prerequisites

- Node.js 18+ and npm
- Python 3.10+
- Git
- Recommended: WSL Ubuntu or Linux/macOS shell

### 1) Clone and install frontend dependencies

```bash
git clone <your-repo-url>
cd PasswordlessAuth
npm install
```

### 2) Set up backend environment

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors cryptography pyotp qrcode requests
```

If your shell uses only python3 (common on Ubuntu/WSL), use python3 commands consistently.

### 3) Run backend

```bash
cd backend
python3 app.py
```

Backend runs at http://127.0.0.1:5000

### 4) Run frontend

```bash
cd ..
npm run dev
```

Frontend runs on Vite default URL (typically http://127.0.0.1:5173)

### 5) Basic smoke test

- Register a new user on the Login page
- Log in with that user
- Execute operations from Dashboard
- Trigger a high-risk transfer to test STEP_UP
- Check audit log integrity views

## API Overview

Primary backend routes include:

- POST /register
- POST /challenge
- POST /login
- POST /operation-challenge
- POST /execute-operation
- POST /stepup-totp
- GET /logs
- GET /verify-logs

Admin/demo routes include:

- POST /admin/login
- GET /admin/logs
- GET /admin/verify-chain
- POST /admin/tamper-log
- POST /admin/restore-logs

## Metrics and Benchmarking

### Frontend Instrumentation

Metrics emitted in browser console with [METRIC] prefix:

- Key Generation Time
- PBKDF2 Derivation Time
- Registration Time
- Total Login Latency
- Operation Challenge RTT
- Step-Up Completion Time

### Backend Benchmark Scripts

Run 30-trial benchmark:

```bash
cd backend
python3 metrics_benchmark.py --base-url http://127.0.0.1:5000 --trials 30 --output metrics_run1.json
python3 metrics_benchmark.py --base-url http://127.0.0.1:5000 --trials 30 --output metrics_run2.json
python3 metrics_benchmark.py --base-url http://127.0.0.1:5000 --trials 30 --output metrics_run3.json
```

Aggregate run summaries:

```bash
python3 aggregate_benchmarks.py metrics_run1.json metrics_run2.json metrics_run3.json --output aggregate_summary.json
```

Run nonce-expiry validation (example 5 attempts):

```bash
python3 metrics_benchmark.py --base-url http://127.0.0.1:5000 --trials 30 --include-nonce-expiry --nonce-expiry-attempts 5 --output metrics_nonce_5.json
```

Offline risk policy simulation:

```bash
python3 simulate_risk.py
```

Raw frontend metrics parser:

```bash
python3 calc_frontend_stats.py
```

## Attack Simulation

Root-level attack demo script:

```bash
python3 attack_demo.py
```

Includes scenarios such as:

- Login nonce replay
- Forged signature attempt
- Wrong-key signature attempt
- Context tampering
- Operation nonce replay
- Audit log tampering detection

## Troubleshooting

### Import errors (Flask, requests, pyotp, qrcode)

Install backend dependencies in your active environment:

```bash
pip install flask flask-cors cryptography pyotp qrcode requests
```

### Port issues

- Ensure backend is available on 127.0.0.1:5000
- Ensure frontend is running on Vite URL

### Database reset for clean testing

If needed, stop backend and remove the local DB (data loss):

```bash
cd backend
rm -f securebank.db
python3 app.py
```

## Contributors

- Sakshee Ujjwal Kumat
- Aishwarya B
- Janhavi S


## Roadmap Ideas

- Move nonce/session state to Redis or persistent store
- Add mTLS/service auth for backend components
- Improve anti-automation with stronger server-verifiable signals
- Add CI workflow for benchmark consistency checks
- Introduce structured observability (OpenTelemetry/log aggregation)

---

