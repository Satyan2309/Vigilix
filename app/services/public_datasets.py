from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from app.config import ROOT_DIR
from app.services.ingestion import parse_log_content
from app.schemas import NormalizedEvent

# Fixed, reviewed source URL. Do not accept user-provided URLs here (avoids SSRF).
DATASET_RAW_URL = (
    "https://raw.githubusercontent.com/ryan91021/cloudtrail-anomaly-detection/main/data/dataset.csv"
)
DATASET_REPOSITORY_URL = "https://github.com/ryan91021/cloudtrail-anomaly-detection"
DATASET_BLOB_URL = (
    "https://github.com/ryan91021/cloudtrail-anomaly-detection/blob/main/data/dataset.csv"
)
DATASET_DIR = ROOT_DIR / "data" / "external_datasets" / "cloudtrail-anomaly-detection"
DATASET_PATH = DATASET_DIR / "dataset.csv"
METADATA_PATH = DATASET_DIR / "SOURCE_METADATA.json"
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
MAX_DATASET_EVENTS = 30_000


class PublicDatasetError(RuntimeError):
    """A safe, user-displayable error related to public dataset import."""


def _download_dataset() -> tuple[bytes, dict[str, Any]]:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[bytes] = []
    total = 0
    try:
        with requests.get(DATASET_RAW_URL, stream=True, timeout=(8, 45)) as response:
            response.raise_for_status()
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_DOWNLOAD_BYTES:
                raise PublicDatasetError("Public dataset download exceeds the 50 MB safety limit.")
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise PublicDatasetError("Public dataset download exceeded the 50 MB safety limit.")
                chunks.append(chunk)
    except PublicDatasetError:
        raise
    except requests.RequestException as exc:
        raise PublicDatasetError(
            "Could not download the public CloudTrail dataset. Check your internet connection and try again, "
            "or upload a compatible CSV file manually."
        ) from exc
    content = b"".join(chunks)
    if not content:
        raise PublicDatasetError("The remote response was empty.")
    # Inspect the header only, allowing both classic CloudTrail CamelCase columns and
    # anonymized research exports with lowercase column names (e.g. eventtime/eventname).
    try:
        header_line = content.splitlines()[0].decode("utf-8-sig", errors="strict")
        header = next(csv.reader([header_line]))
    except Exception as exc:
        raise PublicDatasetError("The downloaded dataset is not valid UTF-8 CSV.") from exc
    header_lower = {column.strip().lower() for column in header}
    if not ("eventname" in header_lower or "event_name" in header_lower):
        raise PublicDatasetError("The downloaded CSV is missing the expected eventName/eventname column.")

    DATASET_PATH.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    metadata = {
        "dataset_name": "Anonymized AWS CloudTrail management event export",
        "repository": DATASET_REPOSITORY_URL,
        "source_file": DATASET_BLOB_URL,
        "raw_download_url": DATASET_RAW_URL,
        "license": "MIT (as declared by source repository)",
        "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
        "file_name": DATASET_PATH.name,
        "bytes": len(content),
        "sha256": sha256,
        "note": (
            "Public research/demo dataset from a personal AWS sandbox; source README reports 26,550 events "
            "from 2026-01-07 through 2026-02-25, anonymized source IPs, no account IDs/ARNs/access keys/user names, "
            "and one documented suspicious sequence. It is not the current user's AWS telemetry."
        ),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return content, metadata


def load_public_cloudtrail_dataset(
    *, max_events: int = 26_550, download_if_missing: bool = True, force_download: bool = False
) -> tuple[list[NormalizedEvent], dict[str, Any]]:
    """Load public anonymized CloudTrail CSV and mark all records with provenance."""
    if max_events < 1 or max_events > MAX_DATASET_EVENTS:
        raise PublicDatasetError(f"max_events must be between 1 and {MAX_DATASET_EVENTS}.")

    metadata: dict[str, Any] = {}
    if force_download or not DATASET_PATH.exists():
        if not download_if_missing:
            raise PublicDatasetError("Dataset is not downloaded yet. Choose download_if_missing or upload a CSV file.")
        content, metadata = _download_dataset()
    else:
        content = DATASET_PATH.read_bytes()
        if not content:
            raise PublicDatasetError("The cached public dataset file is empty. Retry with force_download=true.")
        if METADATA_PATH.exists():
            try:
                metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                metadata = {}
        if not metadata:
            metadata = {
                "dataset_name": "Anonymized AWS CloudTrail management event export",
                "repository": DATASET_REPOSITORY_URL,
                "source_file": DATASET_BLOB_URL,
                "license": "MIT (as declared by source repository)",
                "cached_file": str(DATASET_PATH.relative_to(ROOT_DIR)),
                "sha256": hashlib.sha256(content).hexdigest(),
            }

    try:
        events = parse_log_content("public_cloudtrail_dataset.csv", content)
    except (ValueError, UnicodeError, csv.Error) as exc:
        raise PublicDatasetError(f"Downloaded dataset could not be parsed: {exc}") from exc

    total_records = len(events)
    # Preserve the source README's documented suspicious sequence when a smaller
    # import cap is requested, then fill the remaining quota with newest records.
    if max_events < total_records:
        documented_incident = [
            event for event in events
            if event.event_time.replace(" ", "T", 1).startswith("2026-01-26T03:")
            and event.event_name in {"AssumeRole", "StopLogging", "DeleteTrail"}
        ]
        protected_ids = {event.event_id for event in documented_incident}
        remaining = [event for event in events if event.event_id not in protected_ids]
        remaining.sort(key=lambda event: (event.event_time == "unknown", event.event_time), reverse=True)
        selected_ids = {event.event_id for event in documented_incident[:max_events]}
        selected = list(documented_incident[:max_events])
        for event in remaining:
            if len(selected) >= max_events:
                break
            if event.event_id not in selected_ids:
                selected.append(event)
                selected_ids.add(event.event_id)
        events = selected

    events = [
        event.model_copy(update={
            "ingestion_source": "public_anonymized_cloudtrail",
            "source_ref": DATASET_BLOB_URL,
            "provider": "aws",
        })
        for event in events
    ]
    metadata = {
        **metadata,
        "source": DATASET_BLOB_URL,
        "license": metadata.get("license", "MIT (as declared by source repository)"),
        "total_records_in_file": total_records,
        "records_selected_for_import": len(events),
        "max_events_requested": max_events,
        "anonymized_public_research_data": True,
    }
    return events, metadata
