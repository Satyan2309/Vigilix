from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
_env_path = ROOT_DIR / ".env"
_env_example_path = ROOT_DIR / ".env.example"

# Automatically bootstrap .env from .env.example with a generated JWT secret if .env is missing
if not _env_path.exists() and _env_example_path.exists():
    try:
        _example_text = _env_example_path.read_text(encoding="utf-8")
        _auto_secret = secrets.token_urlsafe(48)
        if "JWT_SECRET_KEY=" in _example_text:
            _new_text = _example_text.replace("JWT_SECRET_KEY=", f"JWT_SECRET_KEY={_auto_secret}", 1)
        else:
            _new_text = _example_text + f"\nJWT_SECRET_KEY={_auto_secret}\n"
        _env_path.write_text(_new_text, encoding="utf-8")
    except Exception:
        pass

load_dotenv(_env_path)


def _path_from_env(name: str, default: str) -> Path:
    path = Path(os.getenv(name, default))
    return path if path.is_absolute() else (ROOT_DIR / path).resolve()


LLM_PROVIDER = os.getenv("LLM_PROVIDER", "nvidia").strip().lower()
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "").strip()
NVIDIA_MODEL = os.getenv("NVIDIA_MODEL", "minimaxai/minimax-m3.1-flash").strip()
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").strip()
NVIDIA_EMBEDDING_MODEL = os.getenv("NVIDIA_EMBEDDING_MODEL", "nvidia/nv-embedqa-e5-v5").strip()
HF_TOKEN = os.getenv("HF_TOKEN", "").strip()
HF_MODEL = os.getenv("HF_MODEL", "meta-llama/Llama-3.3-70B-Instruct").strip()
HF_BASE_URL = os.getenv("HF_BASE_URL", "https://router.huggingface.co/v1").strip()
EMBEDDING_PROVIDER = os.getenv("EMBEDDING_PROVIDER", "auto").strip().lower()
_default_db = (ROOT_DIR / "data" / "cloudsentry.db") if (ROOT_DIR / "data" / "cloudsentry.db").exists() else (ROOT_DIR / "data" / "vigilix.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{_default_db.as_posix()}").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

CHROMA_PERSIST_DIR = _path_from_env("CHROMA_PERSIST_DIR", "./data/chroma")
KNOWLEDGE_DIR = _path_from_env("KNOWLEDGE_DIR", "./data/knowledge")
SAMPLE_LOGS_DIR = _path_from_env("SAMPLE_LOGS_DIR", "./data/sample_logs")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").strip()

# Resilient JWT secret: if empty or < 32 chars, auto-generate a fallback secret so auth never crashes
_configured_jwt_secret = os.getenv("JWT_SECRET_KEY", "").strip()
IS_DEV_JWT_SECRET = False
if len(_configured_jwt_secret) < 32:
    JWT_SECRET_KEY = secrets.token_urlsafe(48)
    IS_DEV_JWT_SECRET = True
else:
    JWT_SECRET_KEY = _configured_jwt_secret

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256").strip()
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "720"))
CHAT_TEMPERATURE = float(os.getenv("CHAT_TEMPERATURE", "0.1"))
CHAT_MAX_TOKENS = int(os.getenv("CHAT_MAX_TOKENS", "700"))
CHAT_HISTORY_TURNS = int(os.getenv("CHAT_HISTORY_TURNS", "4"))
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "4"))


def llm_is_configured() -> bool:
    if LLM_PROVIDER == "nvidia":
        return bool(NVIDIA_API_KEY)
    if LLM_PROVIDER == "huggingface":
        return bool(HF_TOKEN)
    return False


def embeddings_mode() -> str:
    if EMBEDDING_PROVIDER == "local":
        return "hash"
    if EMBEDDING_PROVIDER == "nvidia":
        return "nvidia" if NVIDIA_API_KEY else "hash"
    return "nvidia" if NVIDIA_API_KEY else "hash"
