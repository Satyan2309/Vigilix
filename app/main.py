from __future__ import annotations

import collections as _collections
import json
import logging
import os
import time as _time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vigilix")

_chat_calls: dict[str, list[float]] = _collections.defaultdict(list)
_CHAT_MAX_PER_MIN = 20

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import (
    DATABASE_URL, IS_DEV_JWT_SECRET, LLM_PROVIDER, MAX_UPLOAD_MB,
    ROOT_DIR, SAMPLE_LOGS_DIR, embeddings_mode, llm_is_configured,
)
from app.schemas import (
    ChatRequest, DemoLoadRequest, HealthResponse, IncidentActionToggle, IncidentStatusUpdate,
    InvestigateRequest, KnowledgeIndexRequest, LoginRequest, NormalizedEvent, ProfileUpdateRequest,
    RegisterRequest, RoleUpdateRequest,
)
from app.services.auth import (
    login_account, public_user, register_account, resolve_token,
)
from app.services.aws_connectors import (
    aws_error_message, get_aws_status, sync_cloudtrail_events,
    sync_cloudtrail_s3_logs, sync_guardduty_findings, sync_securityhub_findings,
)
from app.services.chat import answer_chat, stream_chat
from app.services.ingestion import parse_log_content
from app.services.investigation import run_investigation
from app.services.public_datasets import PublicDatasetError, load_public_cloudtrail_dataset
from app.services.rag import index_info, index_knowledge, retrieve_knowledge
from app.services.storage import (
    clear_events, count_events, delete_incident, get_incident, get_telemetry_stats,
    get_user_by_id, init_db, list_chat_messages, list_events, list_incidents,
    list_users, save_chat_message, save_events, save_incident,
    toggle_incident_action, update_incident_status, update_user_profile, update_user_role,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Vigilix AI starting up. Database: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL)
    init_db()
    yield


app = FastAPI(
    title="Vigilix AI API",
    version="0.2.0",
    description="RAG-assisted AWS cloud security triage, continuous intelligent monitoring, and real-time copilot API.",
    lifespan=lifespan,
)

from fastapi.middleware.cors import CORSMiddleware

_cors_origins_raw = os.getenv("CORS_ORIGINS", "").strip()
_allowed_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$|^https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10 MB
            return JSONResponse(status_code=413, content={"detail": "Request body too large."})
    return await call_next(request)


@app.middleware("http")
async def authenticate_requests(request: Request, call_next):
    if request.method.upper() == "OPTIONS":
        return await call_next(request)
    path = request.url.path
    public_paths = {"/", "/api/v1/health", "/api/v1/auth/register", "/api/v1/auth/login"}
    if path in public_paths or path.startswith("/docs") or path.startswith("/openapi.json") or path.startswith("/redoc"):
        return await call_next(request)
    if path.startswith("/api/"):
        authorization = request.headers.get("Authorization", "")
        if not authorization.lower().startswith("bearer "):
            return JSONResponse(status_code=401, content={"detail": "Authentication required. Please sign in."})
        user = resolve_token(authorization.split(" ", 1)[1].strip())
        if not user:
            return JSONResponse(status_code=401, content={"detail": "Session is invalid or expired. Please sign in again."})
        request.state.user = user
        if path.startswith("/api/v1/admin/") and user.get("role") != "admin":
            return JSONResponse(status_code=403, content={"detail": "Administrator role required."})
        write_prefixes = ("/api/v1/ingest/", "/api/v1/demo/", "/api/v1/datasets/", "/api/v1/incidents/investigate", "/api/v1/knowledge/index", "/api/v1/aws/")
        if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith(write_prefixes) and user.get("role") == "viewer":
            return JSONResponse(status_code=403, content={"detail": "Your viewer role does not permit this action."})
    return await call_next(request)


def _owner(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return str(user["id"])


@app.post("/api/v1/auth/register", tags=["authentication"])
def register(request: RegisterRequest) -> dict[str, Any]:
    try:
        user = register_account(request.email, request.password, request.full_name)
        return {"user": user, "message": "Account created. Please sign in."}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/auth/login", tags=["authentication"])
def login(request: LoginRequest, http_request: Request) -> dict[str, Any]:
    client_ip = http_request.client.host if http_request.client else "127.0.0.1"
    try:
        return login_account(request.email, request.password, client_ip=client_ip)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/auth/me", tags=["authentication"])
def me(request: Request) -> dict[str, Any]:
    user_id = _owner(request)
    row = get_user_by_id(user_id)
    if not row:
        raise HTTPException(status_code=401, detail="User account no longer exists.")
    return {"user": public_user(row)}


@app.patch("/api/v1/auth/profile", tags=["authentication"])
def update_profile(payload: ProfileUpdateRequest, request: Request) -> dict[str, Any]:
    row = update_user_profile(_owner(request), payload.full_name)
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user": public_user(row)}


@app.get("/api/v1/admin/users", tags=["administration"])
def admin_list_users(request: Request) -> dict[str, Any]:
    _owner(request)
    return {"users": [public_user(row) for row in list_users()]}


@app.patch("/api/v1/admin/users/{user_id}/role", tags=["administration"])
def admin_update_role(user_id: str, payload: RoleUpdateRequest, request: Request) -> dict[str, Any]:
    _owner(request)
    if user_id == _owner(request) and payload.role != "admin":
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator role.")
    row = update_user_role(user_id, payload.role)
    if not row:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"user": public_user(row)}


@app.post("/api/v1/chat", tags=["chat"])
def chat(payload: ChatRequest, request: Request) -> dict[str, Any]:
    owner_id = _owner(request)
    # Rate limit chat
    _now = _time.time()
    _calls = [t for t in _chat_calls[owner_id] if _now - t < 60]
    _chat_calls[owner_id] = _calls
    if len(_calls) >= _CHAT_MAX_PER_MIN:
        raise HTTPException(status_code=429, detail="Chat rate limit exceeded. Please wait before sending more messages.")
    _chat_calls[owner_id].append(_now)
    history = payload.history or list_chat_messages(owner_id, payload.session_id, limit=8)
    try:
        result = answer_chat(payload.question, owner_id, history)
        save_chat_message(owner_id, payload.session_id, "user", payload.question)
        save_chat_message(owner_id, payload.session_id, "assistant", result["answer"])
        return {**result, "session_id": payload.session_id}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Chat request failed: {type(exc).__name__}: {str(exc)[:250]}") from exc


@app.post("/api/v1/chat/stream", tags=["chat"])
def chat_stream(payload: ChatRequest, request: Request):
    owner_id = _owner(request)
    # Rate limit chat
    _now = _time.time()
    _calls = [t for t in _chat_calls[owner_id] if _now - t < 60]
    _chat_calls[owner_id] = _calls
    if len(_calls) >= _CHAT_MAX_PER_MIN:
        raise HTTPException(status_code=429, detail="Chat rate limit exceeded. Please wait before sending more messages.")
    _chat_calls[owner_id].append(_now)
    history = payload.history or list_chat_messages(owner_id, payload.session_id, limit=8)

    def generate():
        chunks = []
        try:
            for chunk in stream_chat(payload.question, owner_id, history):
                chunks.append(chunk)
                yield "data: " + json.dumps({"token": chunk}, ensure_ascii=False) + "\n\n"
            answer = "".join(chunks)
            save_chat_message(owner_id, payload.session_id, "user", payload.question)
            save_chat_message(owner_id, payload.session_id, "assistant", answer)
            yield "data: " + json.dumps({"done": True, "session_id": payload.session_id}) + "\n\n"
        except Exception as exc:
            yield "data: " + json.dumps({"error": f"{type(exc).__name__}: {str(exc)[:250]}"}) + "\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {"name": "Vigilix AI", "status": "running", "docs": "/docs", "health": "/api/v1/health"}


@app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    notes: list[str] = []
    if IS_DEV_JWT_SECRET:
        notes.append("Using auto-generated development JWT secret. Set JWT_SECRET_KEY in .env for production.")
    if not llm_is_configured():
        notes.append("No hosted LLM credentials detected; AI Copilot operates in local intelligence mode.")
    if embeddings_mode() == "hash":
        notes.append("Using lightweight local hashing embeddings. Configure NVIDIA_API_KEY and EMBEDDING_PROVIDER=auto for hosted semantic embeddings.")
    notes.append("AWS integration is optional; use synthetic sample logs until you explicitly configure read-only AWS access.")
    db_name = "SQLite" if DATABASE_URL.startswith("sqlite") else "configured SQL database"
    return HealthResponse(
        status="ok",
        llm_provider=LLM_PROVIDER,
        llm_mode=LLM_PROVIDER if llm_is_configured() else "local_intelligence",
        embeddings_mode=embeddings_mode(),
        database=db_name,
        notes=notes,
    )


ALLOWED_LOG_EXTENSIONS = {".json", ".jsonl", ".gz", ".csv", ".txt", ".log"}


@app.post("/api/v1/ingest/upload", tags=["ingestion"])
async def upload_logs(request: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    filename = file.filename or "uploaded.log"
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_LOG_EXTENSIONS and not filename.lower().endswith(".json.gz"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_LOG_EXTENSIONS))}",
        )
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_MB} MB upload limit.")
    try:
        events = parse_log_content(filename, content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    inserted = save_events(events, owner_id=_owner(request))
    providers: dict[str, int] = {}
    for event in events:
        providers[event.provider] = providers.get(event.provider, 0) + 1
    return {"filename": filename, "parsed_events": len(events), "new_events": inserted, "total_events": count_events(_owner(request)), "providers": providers}


@app.post("/api/v1/demo/load", tags=["ingestion"])
def load_demo(request: DemoLoadRequest, http_request: Request) -> dict[str, Any]:
    files: list[Path] = []
    if request.scenario in ("suspicious", "mixed"):
        files.extend([SAMPLE_LOGS_DIR / "cloudtrail_suspicious.json", SAMPLE_LOGS_DIR / "guardduty_findings.json"])
    if request.scenario in ("benign", "mixed"):
        files.append(SAMPLE_LOGS_DIR / "cloudtrail_benign.json")
    all_events: list[NormalizedEvent] = []
    for path in files:
        if not path.exists():
            raise HTTPException(status_code=500, detail=f"Demo dataset missing: {path.name}")
        try:
            all_events.extend(parse_log_content(path.name, path.read_bytes()))
        except ValueError as exc:
            raise HTTPException(status_code=500, detail=f"Could not parse demo file {path.name}: {exc}") from exc
    all_events = [event.model_copy(update={"ingestion_source": "synthetic_demo", "source_ref": f"demo:{event.source_ref or event.event_name}"}) for event in all_events]
    inserted = save_events(all_events, owner_id=_owner(http_request))
    return {"scenario": request.scenario, "parsed_events": len(all_events), "new_events": inserted, "total_events": count_events(_owner(http_request)), "files": [path.name for path in files], "data_mode": "synthetic_demo"}


@app.post("/api/v1/datasets/public-cloudtrail/import", tags=["datasets"])
def import_public_cloudtrail_dataset(request: Request, max_events: int = 26550, force_download: bool = False) -> dict[str, Any]:
    try:
        events, metadata = load_public_cloudtrail_dataset(
            max_events=max_events, download_if_missing=True, force_download=force_download
        )
    except PublicDatasetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    inserted = save_events(events, owner_id=_owner(request))
    return {
        "source": "public_anonymized_cloudtrail",
        "data_mode": "public_anonymized_research_data",
        "parsed_events": len(events),
        "new_events": inserted,
        "total_events": count_events(_owner(request)),
        "metadata": metadata,
        "notice": "This is public anonymized research data, not live telemetry from your AWS account.",
    }


@app.get("/api/v1/events", tags=["events"])
def get_events(
    request: Request,
    limit: int = 200,
    from_time: str | None = None,
    to_time: str | None = None,
    event_name: str | None = None,
    principal: str | None = None,
    source_ip: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 1000")
    if from_time:
        from_time = from_time.strip()
        if len(from_time) == 10:
            from_time = f"{from_time}T00:00:00"
    if to_time:
        to_time = to_time.strip()
        if len(to_time) == 10:
            try:
                from datetime import date, timedelta
                to_time = (date.fromisoformat(to_time) + timedelta(days=1)).isoformat() + "T00:00:00"
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="to_time must be an ISO date or timestamp") from exc
    events = list_events(
        limit=limit, from_time=from_time, to_time=to_time, event_name=event_name,
        principal=principal, source_ip=source_ip, provider=provider, owner_id=_owner(request),
    )
    return {"count": len(events), "total_count": count_events(_owner(request)), "events": [event.model_dump(mode="json") for event in events]}


@app.get("/api/v1/detections/preview", tags=["detections"])
def preview_detections(request: Request, limit: int = 200) -> dict[str, Any]:
    events = list_events(limit=max(1, min(limit, 1000)), owner_id=_owner(request))
    from app.services.detection import analyze_events
    return analyze_events(events)


@app.post("/api/v1/incidents/investigate", tags=["investigations"])
def investigate(request: InvestigateRequest, http_request: Request) -> dict[str, Any]:
    events = list_events(limit=request.limit, event_ids=request.event_ids, owner_id=_owner(http_request))
    if not events:
        raise HTTPException(status_code=400, detail="No events found. Upload logs or load the sample dataset first.")
    try:
        report = run_investigation(events, title=request.title)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {type(exc).__name__}: {str(exc)[:350]}") from exc
    save_incident(report, owner_id=_owner(http_request))
    return report


@app.get("/api/v1/incidents", tags=["investigations"])
def get_incidents(request: Request, limit: int = 50) -> dict[str, Any]:
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")
    incidents = list_incidents(limit=limit, owner_id=_owner(request))
    return {"count": len(incidents), "incidents": incidents}


@app.get("/api/v1/incidents/{incident_id}", tags=["investigations"])
def get_incident_by_id(incident_id: str, request: Request) -> dict[str, Any]:
    report = get_incident(incident_id, owner_id=_owner(request))
    if not report:
        raise HTTPException(status_code=404, detail="Incident report not found.")
    return report


@app.patch("/api/v1/incidents/{incident_id}/status", tags=["investigations"])
def update_status(incident_id: str, request: Request, payload: IncidentStatusUpdate) -> dict[str, Any]:
    status = payload.status
    updated = update_incident_status(incident_id, status, owner_id=_owner(request))
    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return updated


@app.patch("/api/v1/incidents/{incident_id}/actions/{action_idx}", tags=["investigations"])
def toggle_action(incident_id: str, action_idx: int, request: Request, payload: IncidentActionToggle) -> dict[str, Any]:
    completed = payload.completed
    updated = toggle_incident_action(incident_id, action_idx, completed, owner_id=_owner(request))
    if not updated:
        raise HTTPException(status_code=404, detail="Incident or action not found.")
    return updated


@app.delete("/api/v1/incidents/{incident_id}", tags=["investigations"])
def remove_incident(incident_id: str, request: Request) -> dict[str, Any]:
    ok = delete_incident(incident_id, owner_id=_owner(request))
    if not ok:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return {"message": "Incident report removed.", "incident_id": incident_id}


@app.delete("/api/v1/events/clear", tags=["events"])
def clear_workspace_events(request: Request) -> dict[str, Any]:
    cleared = clear_events(owner_id=_owner(request))
    return {"message": "Workspace telemetry cleared.", "cleared_events": cleared}


@app.get("/api/v1/telemetry/stats", tags=["telemetry"])
def get_stats(request: Request) -> dict[str, Any]:
    return get_telemetry_stats(owner_id=_owner(request))


@app.get("/api/v1/knowledge", tags=["knowledge"])
def knowledge_status() -> dict[str, Any]:
    return index_info()


@app.post("/api/v1/knowledge/index", tags=["knowledge"])
def index_knowledge_base(request: KnowledgeIndexRequest) -> dict[str, Any]:
    try:
        result = index_knowledge(force_reindex=request.force_reindex)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Knowledge indexing failed: {type(exc).__name__}: {str(exc)[:350]}") from exc
    return {**result, "knowledge": index_info()}


@app.get("/api/v1/knowledge/search", tags=["knowledge"])
def search_knowledge(q: str, k: int = 5) -> dict[str, Any]:
    if not q.strip():
        raise HTTPException(status_code=400, detail="Query q must not be empty.")
    if k < 1 or k > 10:
        raise HTTPException(status_code=400, detail="k must be between 1 and 10.")
    try:
        results = retrieve_knowledge(q, k=k)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Knowledge retrieval failed: {type(exc).__name__}: {str(exc)[:350]}") from exc
    return {"query": q, "count": len(results), "results": results}


@app.get("/api/v1/aws/status", tags=["aws-connectors"])
def aws_status(region: str = "ap-south-1", profile: str | None = None) -> dict[str, Any]:
    try:
        return get_aws_status(region=region, profile=profile)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=aws_error_message(exc)) from exc


@app.post("/api/v1/aws/cloudtrail/sync", tags=["aws-connectors"])
def sync_cloudtrail(request: Request, region: str = "ap-south-1", hours: int = 24, limit: int = 200, profile: str | None = None) -> dict[str, Any]:
    try:
        events = sync_cloudtrail_events(region=region, hours=hours, limit=limit, profile=profile)
        inserted = save_events(events, owner_id=_owner(request))
        return {"source": "cloudtrail", "region": region, "requested_hours": hours, "fetched_events": len(events), "new_events": inserted, "total_events": count_events(_owner(request)), "data_mode": "live_aws"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=aws_error_message(exc)) from exc


@app.post("/api/v1/aws/cloudtrail/s3-sync", tags=["aws-connectors"])
def sync_cloudtrail_s3(request: Request, bucket: str, prefix: str = "", region: str = "ap-south-1", hours: int = 24, max_objects: int = 20, profile: str | None = None) -> dict[str, Any]:
    try:
        events, source_metadata = sync_cloudtrail_s3_logs(bucket=bucket, prefix=prefix, region=region, hours=hours, max_objects=max_objects, profile=profile)
        inserted = save_events(events, owner_id=_owner(request))
        return {"source": "cloudtrail_s3", "bucket": bucket, "prefix": prefix, "region": region, "requested_hours": hours, "fetched_events": len(events), "new_events": inserted, "total_events": count_events(_owner(request)), "data_mode": "live_aws", "source_metadata": source_metadata}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=aws_error_message(exc)) from exc


@app.post("/api/v1/aws/guardduty/sync", tags=["aws-connectors"])
def sync_guardduty(request: Request, region: str = "ap-south-1", limit: int = 50, profile: str | None = None) -> dict[str, Any]:
    try:
        events = sync_guardduty_findings(region=region, limit=limit, profile=profile)
        inserted = save_events(events, owner_id=_owner(request))
        return {"source": "guardduty", "region": region, "fetched_findings": len(events), "new_events": inserted, "total_events": count_events(_owner(request)), "data_mode": "live_aws"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=aws_error_message(exc)) from exc


@app.post("/api/v1/aws/securityhub/sync", tags=["aws-connectors"])
def sync_securityhub(request: Request, region: str = "ap-south-1", limit: int = 100, profile: str | None = None) -> dict[str, Any]:
    try:
        events = sync_securityhub_findings(region=region, limit=limit, profile=profile)
        inserted = save_events(events, owner_id=_owner(request))
        return {"source": "securityhub", "region": region, "fetched_findings": len(events), "new_events": inserted, "total_events": count_events(_owner(request)), "data_mode": "live_aws"}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=aws_error_message(exc)) from exc


# ---------------------------------------------------------------------------
# Static Frontend SPA Serving (when production-built frontend/dist exists)
# ---------------------------------------------------------------------------
_frontend_dist = ROOT_DIR / "frontend" / "dist"
if _frontend_dist.exists() and (_frontend_dist / "index.html").exists():
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    if (_frontend_dist / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(_frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("openapi.json") or full_path.startswith("redoc"):
            raise HTTPException(status_code=404, detail="Not Found")
        file_candidate = _frontend_dist / full_path
        if full_path and file_candidate.is_file():
            return FileResponse(file_candidate)
        return FileResponse(_frontend_dist / "index.html")
