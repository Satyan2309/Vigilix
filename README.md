# Vigilix AI

**Continuous Intelligent Security Monitoring — RAG-powered AWS cloud-security triage, investigation, and conversational copilot** built with Python, FastAPI, React + Vite, LangChain, LangGraph, ChromaDB, SQLAlchemy, and Neon PostgreSQL.

Vigilix AI ingests CloudTrail-style audit events, S3 archives, GuardDuty findings, and Security Hub findings, applies transparent detection/correlation rules, retrieves related security guidance with RAG, and produces an investigation report containing observed signals, hypotheses, source references, and interactive defensive action checklists.

> **Portfolio prototype notice:** The included datasets are synthetic and public research logs. Severity is a heuristic triage priority, not a probability of compromise. The application does not automatically remediate AWS resources. Validate reports with authoritative telemetry and an authorized analyst.

## Features

- **Cyber-Glassmorphism SOC Dashboard:** Built with React 19 + Vite, Lucide icons, live event stream virtual pagination, real timestamp histogram distributions, markdown copilot parser, and custom SOC toast alerts.
- **Log Ingestion Engine:** Upload JSON, JSONL, CSV, TXT, and gzip-compressed CloudTrail `.json.gz` logs through the web console or API.
- **Standardized Event Schema:** Normalizes real CloudTrail records, GuardDuty findings, and AWS Security Hub ASFF findings into a unified Pydantic event model.
- **Explainable Correlation Rules:** Detects high-risk AWS operations and correlates suspicious sequences:
  - Access key creation followed by immediate IAM privilege escalations (`AttachUserPolicy`, `PutUserPolicy`).
  - IAM changes correlated with audit trail tampering (`StopLogging`, `DeleteTrail`).
  - Brute force or failed console logins followed by a successful sign-in from external IPs.
  - S3 public bucket policy exposures (`PutBucketPolicy`, `PutBucketAcl`).
  - High-severity GuardDuty findings.
- **LangGraph Multi-Stage Investigation:** detect → retrieve knowledge → optionally retrieve additional context → analyze → validate and structure report.
- **Vector Retrieval & RAG:** LangChain document splitting, vector retrieval, source metadata, and persistent ChromaDB storage.
- **Hybrid AI Copilot & Streaming Chat:** Streams tokens with Server-Sent Events (SSE). Uses NVIDIA NIM hosted models (`minimax-m3.1-flash`) or Hugging Face Inference Providers. Exact count queries execute SQL against the real database rather than hallucinating from a sample.
- **Privacy & Pseudonymization:** Before hosted LLM calls, principal, source IP, resource ARN, and 12-digit AWS account identifiers in event contexts are pseudonymized into deterministic placeholders.
- **Dual-Database Support:** SQLite for instant zero-dependency local runs; Neon Serverless PostgreSQL with auto-reconnecting pooled connections for production.
- **Role-Based Access Control (RBAC):** Argon2 password hashing, JWT bearer tokens, per-user workspace isolation, and roles (`admin`, `analyst`, `viewer`).
- **Real-World Research Dataset Support:** Built-in downloader and parser for 26,550 recorded real CloudTrail events from research datasets.

## Architecture

```mermaid
flowchart TD
    A[CloudTrail API / S3 logs / GuardDuty / Security Hub / Uploads] --> B[FastAPI Ingestion Engine]
    B --> C[Parse & Normalize with Pydantic]
    C --> D[(SQLite / Neon PostgreSQL Store)]
    C --> E[Python Detection & Event Correlation]
    E --> F[LangGraph Investigation Pipeline]
    K[Security Docs / CIS Runbooks / MITRE ATT&CK] --> L[LangChain Loader & Splitter]
    L --> M[Embedding Provider]
    M --> N[(ChromaDB Vector Store)]
    F --> O[LangChain RAG Retriever]
    O <--> N
    F --> P[Hosted NVIDIA NIM / Hugging Face LLM]
    D --> F
    P --> Q[Structured Incident Report]
    Q --> D
    R[React + Vite SOC Console] <--> S[FastAPI REST API]
```

### Separation of Responsibilities

- **Python + SQL:** Parse raw telemetry, sort timelines, execute deterministic rules, and correlate identities/timestamps.
- **LangChain + ChromaDB:** Retrieve relevant security documentation, CIS benchmarks, and detection guidance with source citations.
- **LangGraph:** Coordinate investigation states and conditionally trigger deeper retrieval when initial evidence is sparse.
- **Hosted LLM:** Synthesize observations, formulate hypotheses, and propose remediation actions without direct access to production cloud resources.

---

## 1. Prerequisites

- Python 3.11 or 3.12.
- Node.js 18+ and npm (for frontend development).
- **No local GPU or AWS account is required for demo mode.**
- An NVIDIA API key enables hosted LLM chat + embeddings (get a free key from the [NVIDIA API Catalog](https://build.nvidia.com/)).
- A Hugging Face token is optional if you prefer Hugging Face Inference Providers.

---

## 2. Run Locally (Windows PowerShell)

### Step 1: Set Up Backend

Open PowerShell in the project root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Generate a secure random JWT signing secret and set your NVIDIA API key in `.env`:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Paste the generated string into `JWT_SECRET_KEY` in `.env`:

```dotenv
LLM_PROVIDER=nvidia
NVIDIA_API_KEY=your_nvidia_api_key_here
NVIDIA_MODEL=minimaxai/minimax-m3.1-flash
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
EMBEDDING_PROVIDER=auto
NVIDIA_EMBEDDING_MODEL=nvidia/nv-embedqa-e5-v5
```

Start the FastAPI backend:

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

The API docs are available at <http://127.0.0.1:8000/docs>.

---

### Step 2: Set Up Frontend

Open a second PowerShell terminal in the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open <http://localhost:5173> to access the **Vigilix AI SOC Console**.

Create an account on the login screen. The first registered account automatically becomes the bootstrap `admin`; subsequent accounts receive the `analyst` role.

---

### Cloud Database (Neon PostgreSQL)

SQLite is the default zero-config storage. For production or team environments, set `DATABASE_URL` in `.env` to your Neon pooled connection string:

```dotenv
DATABASE_URL=postgresql://neondb_owner:password@ep-pooler.us-east-2.aws.neon.tech/neondb
```

Vigilix automatically configures a resilient connection pool (`pool_pre_ping=True`, pool size 10, max overflow 20).

---

## 3. Real AWS Data (Optional & Read-Only)

Vigilix supports public research datasets, file uploads, and optional live AWS connectors:

1. **Public Anonymized CloudTrail Dataset:** Built-in downloader imports 26,550 real-world AWS CloudTrail events directly into your database.
2. **CloudTrail Event History API:** Reads management events from the selected AWS Region (last 90 days, read-only).
3. **S3-Delivered CloudTrail Logs:** Reads `.json` and `.json.gz` audit archives directly from an S3 bucket you specify.
4. **Existing GuardDuty & Security Hub Findings:** Pulls active findings from services already enabled in your AWS account.

### Connect an AWS CLI Profile

```powershell
aws configure sso --profile vigilix-readonly
aws sso login --profile vigilix-readonly
```

A sample read-only policy is provided at [`docs/aws-readonly-policy.json`](docs/aws-readonly-policy.json). Vigilix never enables services or makes state-changing API calls on AWS.

---

## 4. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health check & LLM/vector provider status |
| `POST` | `/api/v1/auth/register` | Register an account (first user is bootstrap admin) |
| `POST` | `/api/v1/auth/login` | Authenticate and obtain JWT bearer token |
| `GET` | `/api/v1/auth/me` | Fetch active user profile and role |
| `PATCH` | `/api/v1/auth/profile` | Update profile display name |
| `POST` | `/api/v1/chat` | AI Copilot conversational response |
| `POST` | `/api/v1/chat/stream` | Streaming AI Copilot response (Server-Sent Events) |
| `POST` | `/api/v1/ingest/upload` | Upload `.json`, `.jsonl`, `.csv`, `.txt`, `.json.gz` logs |
| `POST` | `/api/v1/demo/load` | Ingest synthetic scenarios (suspicious, benign, mixed) |
| `POST` | `/api/v1/datasets/public-cloudtrail/import` | Ingest real CloudTrail research dataset |
| `GET` | `/api/v1/events` | Filtered event explorer (pagination, IP, action, principal) |
| `DELETE` | `/api/v1/events/clear` | Clear ingested events for active account |
| `GET` | `/api/v1/detections/preview` | Preview deterministic correlation signals |
| `POST` | `/api/v1/incidents/investigate` | Run LangGraph automated triage & generate report |
| `GET` | `/api/v1/incidents` | List saved incident investigation reports |
| `GET` | `/api/v1/incidents/{incident_id}` | Retrieve specific incident details |
| `PATCH` | `/api/v1/incidents/{incident_id}/status` | Update incident triage state (`open`, `investigating`, `resolved`) |
| `POST` | `/api/v1/incidents/{incident_id}/actions/{action_id}/toggle` | Toggle defensive containment checklist item |
| `DELETE` | `/api/v1/incidents/{incident_id}` | Delete an incident report |
| `GET` | `/api/v1/knowledge` | Vector database indexing status |
| `POST` | `/api/v1/knowledge/index` | Re-index security knowledge corpus into ChromaDB |
| `GET` | `/api/v1/knowledge/search` | Semantic search over indexed security knowledge |
| `GET` | `/api/v1/aws/status` | Verify AWS credentials and read permissions |
| `POST` | `/api/v1/aws/cloudtrail/sync` | Pull management events from CloudTrail Event History |
| `POST` | `/api/v1/aws/cloudtrail/s3-sync` | Ingest delivered CloudTrail `.json.gz` from S3 |
| `POST` | `/api/v1/aws/guardduty/sync` | Ingest active GuardDuty findings |
| `POST` | `/api/v1/aws/securityhub/sync` | Ingest active AWS Security Hub findings |

---

## 5. Automated Tests

Run the full pytest suite (26 integration & unit tests):

```powershell
.\.venv\Scripts\Activate.ps1
pytest -v
```

Tests validate log parsing, gzip decompression, correlation heuristics, authentication tokens, rate limiting, and embedding fallback modes.

---

## 6. Docker & Production Deployment

A production-ready multi-stage `Dockerfile` packages both the React SPA and FastAPI backend into a single container:

```powershell
docker compose up --build
```

Access the full SOC console at **<http://localhost:8000>**.

### Cloud Hosting (Render, Railway, Fly.io, AWS App Runner)

Deploy this repository as a single Docker service and set:

| Variable | Value / Notes |
| :--- | :--- |
| `DATABASE_URL` | Neon PostgreSQL pooled URL |
| `JWT_SECRET_KEY` | 64-character random string |
| `NVIDIA_API_KEY` | NVIDIA NIM API key |
| `LLM_PROVIDER` | `nvidia` |
| `CORS_ORIGINS` | Comma-separated domains if frontend is hosted on a separate URL (e.g. Vercel) |

---

## 7. Security Notes

- **Credential Safety:** Never commit `.env` or credentials. Both `.gitignore` and `.dockerignore` exclude local environment files and databases.
- **Context Pseudonymization:** Vigilix pseudonymizes AWS account numbers, principal identities, and IP addresses before sending prompts to external LLMs.
- **Untrusted Input Protection:** Event payloads and log files are treated as untrusted data to mitigate prompt injection risks.
- **No Automatic Remediation:** Vigilix recommends defense checklists for security analysts; it does not automatically revoke keys or alter cloud configurations without human approval.
