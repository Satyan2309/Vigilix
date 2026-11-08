from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import requests
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_chroma import Chroma
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sklearn.feature_extraction.text import HashingVectorizer

from app.config import (
    CHROMA_PERSIST_DIR, KNOWLEDGE_DIR, NVIDIA_API_KEY,
    NVIDIA_BASE_URL, NVIDIA_EMBEDDING_MODEL, embeddings_mode,
)


class HashingEmbeddings(Embeddings):
    """No-download fallback for demo mode. Lexical, not semantic, embeddings."""
    def __init__(self, n_features: int = 2048) -> None:
        self.vectorizer = HashingVectorizer(
            n_features=n_features,
            alternate_sign=False,
            norm="l2",
            ngram_range=(1, 2),
            token_pattern=r"(?u)\b[a-zA-Z_][a-zA-Z0-9_.:/-]{1,}\b",
        )

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        matrix = self.vectorizer.transform(texts)
        return matrix.toarray().astype(float).tolist()

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


class NvidiaRemoteEmbeddings(Embeddings):
    """Hosted NVIDIA embedding API; embedding inference stays off the laptop."""
    def __init__(self, api_key: str, model: str, base_url: str, timeout: int = 90) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _embed(self, texts: list[str], input_type: str) -> list[list[float]]:
        if not texts:
            return []
        url = f"{self.base_url}/embeddings"
        results: list[tuple[int, list[float]]] = []
        # Modest batches avoid unusually large request payloads.
        for start in range(0, len(texts), 32):
            batch = texts[start:start + 32]
            response = requests.post(
                url,
                headers={"Authorization": f"Bearer {self.api_key}", "Accept": "application/json", "Content-Type": "application/json"},
                json={
                    "model": self.model,
                    "input": batch,
                    "input_type": input_type,
                    "encoding_format": "float",
                    "truncate": "END",
                },
                timeout=self.timeout,
            )
            if response.status_code >= 400:
                raise RuntimeError(f"NVIDIA embedding API failed ({response.status_code}): {response.text[:500]}")
            payload = response.json()
            rows = payload.get("data", [])
            if len(rows) != len(batch):
                raise RuntimeError("NVIDIA embedding API returned an unexpected number of vectors.")
            rows = sorted(rows, key=lambda row: row.get("index", 0))
            for row in rows:
                results.append((start + int(row.get("index", 0)), row["embedding"]))
        results.sort(key=lambda pair: pair[0])
        return [vec for _, vec in results]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        # NVIDIA E5 embeddings specifically distinguish passage and query inputs.
        return self._embed(texts, "passage")

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], "query")[0]


def _embedding_object(mode: str | None = None) -> Embeddings:
    mode = mode or embeddings_mode()
    if mode == "nvidia" and NVIDIA_API_KEY:
        return NvidiaRemoteEmbeddings(
            api_key=NVIDIA_API_KEY,
            model=NVIDIA_EMBEDDING_MODEL,
            base_url=NVIDIA_BASE_URL,
        )
    return HashingEmbeddings()


@lru_cache(maxsize=4)
def get_vectorstore(mode_override: str | None = None) -> Chroma:
    CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    mode = mode_override or embeddings_mode()
    return Chroma(
        collection_name=f"vigilix_{mode}",
        persist_directory=str(CHROMA_PERSIST_DIR),
        embedding_function=_embedding_object(mode),
        collection_metadata={"hnsw:space": "cosine"},
    )


def load_knowledge_documents() -> list[Document]:
    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
    raw_documents: list[Document] = []
    for path in sorted(KNOWLEDGE_DIR.rglob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            continue
        title = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("# ")), path.stem.replace("_", " ").title())
        category_match = re.search(r"^Category:\s*(.+)$", text, flags=re.MULTILINE | re.IGNORECASE)
        url_match = re.search(r"^Reference:\s*(https?://\S+)", text, flags=re.MULTILINE)
        raw_documents.append(Document(
            page_content=text,
            metadata={
                "source": path.name,
                "source_path": str(path.relative_to(KNOWLEDGE_DIR)),
                "title": title,
                "category": category_match.group(1).strip() if category_match else "general",
                "source_url": url_match.group(1).strip() if url_match else "",
            },
        ))
    splitter = RecursiveCharacterTextSplitter(chunk_size=850, chunk_overlap=120, add_start_index=True)
    return splitter.split_documents(raw_documents)


def _index_knowledge_for_mode(force_reindex: bool, mode: str) -> dict[str, int | str]:
    store = get_vectorstore(mode)
    count = store._collection.count()
    if count > 0 and not force_reindex:
        return {"status": "already_indexed", "chunks_indexed": count, "embedding_mode": mode}
    if count > 0 and force_reindex:
        store.delete_collection()
        get_vectorstore.cache_clear()
        store = get_vectorstore(mode)
    documents = load_knowledge_documents()
    if not documents:
        raise RuntimeError(f"No .md knowledge documents found under {KNOWLEDGE_DIR}")
    store.add_documents(documents)
    return {"status": "indexed", "chunks_indexed": len(documents), "embedding_mode": mode}


def index_knowledge(force_reindex: bool = False) -> dict[str, int | str]:
    mode = embeddings_mode()
    try:
        return _index_knowledge_for_mode(force_reindex, mode)
    except Exception as exc:
        # If the configured hosted embedding model is unavailable, keep RAG usable
        # with lexical local embeddings instead of breaking the chat endpoint.
        if mode != "nvidia":
            raise
        result = _index_knowledge_for_mode(force_reindex, "hash")
        result["status"] = "indexed_with_local_fallback" if result["status"] == "indexed" else "using_local_fallback"
        result["fallback_reason"] = f"NVIDIA embeddings unavailable: {type(exc).__name__}"
        return result


def _retrieve_with_mode(query: str, k: int, mode: str) -> list[dict[str, object]]:
    store = get_vectorstore(mode)
    if store._collection.count() == 0:
        _index_knowledge_for_mode(False, mode)
        store = get_vectorstore(mode)
    matches = store.similarity_search_with_score(query, k=k)
    results: list[dict[str, object]] = []
    for doc, score in matches:
        results.append({
            "content": doc.page_content,
            "source": doc.metadata.get("source", "unknown"),
            "title": doc.metadata.get("title", "Untitled source"),
            "category": doc.metadata.get("category", "general"),
            "source_url": doc.metadata.get("source_url", ""),
            "retrieval_distance": round(float(score), 4) if score is not None else None,
        })
    return results


def retrieve_knowledge(query: str, k: int = 5) -> list[dict[str, object]]:
    if not query.strip():
        return []
    mode = embeddings_mode()
    try:
        return _retrieve_with_mode(query, k, mode)
    except Exception:
        if mode != "nvidia":
            raise
        return _retrieve_with_mode(query, k, "hash")


def index_info() -> dict[str, object]:
    mode = embeddings_mode()
    store = get_vectorstore(mode)
    count = store._collection.count()
    effective_mode = mode
    if mode == "nvidia" and count == 0:
        local_store = get_vectorstore("hash")
        if local_store._collection.count() > 0:
            store = local_store
            count = store._collection.count()
            effective_mode = "hash_fallback"
    return {
        "embedding_mode": effective_mode,
        "persist_directory": str(CHROMA_PERSIST_DIR),
        "indexed_chunks": count,
        "knowledge_files": len(list(KNOWLEDGE_DIR.rglob("*.md"))) if KNOWLEDGE_DIR.exists() else 0,
        "local_embedding_note": "Local hashing fallback is active. It is lightweight but lexical rather than transformer-semantic." if effective_mode in ("hash", "hash_fallback") else "Hosted NVIDIA semantic embeddings are configured; confirm the selected model is currently available to your API account.",
    }
