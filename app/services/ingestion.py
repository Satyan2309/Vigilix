from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.schemas import NormalizedEvent

TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")


def _stable_id(record: dict[str, Any]) -> str:
    canonical = json.dumps(record, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _first(*values: Any, default: str = "unknown") -> str:
    for value in values:
        if value is not None and str(value).strip() and str(value).lower() not in {"none", "nan", "nat"}:
            return str(value)
    return default


def _deep_find(obj: Any, keys: set[str]) -> Any:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in keys and value not in (None, ""):
                return value
        for value in obj.values():
            found = _deep_find(value, keys)
            if found not in (None, ""):
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = _deep_find(value, keys)
            if found not in (None, ""):
                return found
    return None


def normalize_cloudtrail(record: dict[str, Any]) -> NormalizedEvent:
    identity = record.get("userIdentity") or {}
    if not isinstance(identity, dict):
        identity = {}
    session = identity.get("sessionContext") or {}
    session_issuer = session.get("sessionIssuer") or {} if isinstance(session, dict) else {}
    request = record.get("requestParameters") or {}
    resources = record.get("resources") or []
    resource = "unknown"
    if isinstance(resources, list) and resources:
        first_resource = resources[0]
        if isinstance(first_resource, dict):
            resource = _first(first_resource.get("ARN"), first_resource.get("arn"), first_resource.get("resourceName"))
        else:
            resource = str(first_resource)
    if resource == "unknown" and isinstance(request, dict):
        resource = _first(
            request.get("bucketName"), request.get("userName"), request.get("roleName"),
            request.get("groupName"), request.get("resourceArn"),
            record.get("requestParameters.bucketName"), record.get("requestParameters.userName"),
            record.get("requestParameters.roleName"), record.get("resources.0.ARN"),
            record.get("resources.0.resourceName"),
        )
    # Prefer IAM username when present so it can match GuardDuty's userName field;
    # assume-role identities generally fall back to ARN/principal ID.
    principal = _first(
        identity.get("userName"), record.get("userIdentity.userName"), record.get("useridentity.username"),
        identity.get("arn"), record.get("userIdentity.arn"), record.get("useridentity.arn"),
        identity.get("principalId"), record.get("userIdentity.principalId"), record.get("useridentity.principalid"),
        session_issuer.get("arn") if isinstance(session_issuer, dict) else None,
        identity.get("accountId"), record.get("userIdentity.accountId"), record.get("useridentity.accountid"),
        record.get("principal"), record.get("userName"),
    )
    event_time = _first(record.get("eventTime"), record.get("eventtime"), record.get("event_time"), record.get("time"), record.get("timestamp"), default="unknown")
    # Research CSV exports sometimes serialize UTC timestamps with a space separator;
    # normalize that separator so lexical database date filters work consistently.
    if len(event_time) > 10 and event_time[10] == " ":
        event_time = event_time[:10] + "T" + event_time[11:]
    return NormalizedEvent(
        event_id=_first(record.get("eventID"), record.get("eventId"), record.get("eventid"), record.get("event_id"), record.get("id"), default=_stable_id(record)),
        event_time=event_time,
        event_name=_first(record.get("eventName"), record.get("eventname"), record.get("event_name"), record.get("name"), record.get("type"), default="UnknownEvent"),
        event_source=_first(record.get("eventSource"), record.get("eventsource"), record.get("event_source"), record.get("source"), record.get("eventCategory")),
        principal=principal,
        source_ip=_first(record.get("sourceIPAddress"), record.get("sourceipaddress"), record.get("sourceIpAddress"), record.get("source_ip")),
        region=_first(record.get("awsRegion"), record.get("awsregion"), record.get("region")),
        resource=_first(record.get("resource"), resource),
        error_code=_first(record.get("errorCode"), record.get("errorcode"), record.get("error_code"), default="") or None,
        provider="aws",
        severity=None,
        description=_first(record.get("eventDescription"), record.get("description"), record.get("message"), default=""),
        raw=record,
    )


def normalize_guardduty(record: dict[str, Any]) -> NormalizedEvent:
    service = record.get("service") or {}
    resource_data = record.get("resource") or {}
    access_key = _deep_find(resource_data, {"userName", "principalId", "arn", "instanceId", "resourceId"})
    ip = _deep_find(service, {"ipAddressV4", "remoteIpAddress", "sourceIpAddress"})
    severity_raw = record.get("severity")
    try:
        severity = float(severity_raw) if severity_raw is not None else None
    except (TypeError, ValueError):
        severity = None
    return NormalizedEvent(
        event_id=_first(record.get("id"), record.get("findingId"), default=_stable_id(record)),
        event_time=_first(record.get("updatedAt"), record.get("createdAt"), record.get("eventTime"), default="unknown"),
        event_name="GuardDutyFinding",
        event_source="guardduty.amazonaws.com",
        principal=str(access_key) if access_key else "unknown",
        source_ip=str(ip) if ip else "unknown",
        region=_first(record.get("region")),
        resource=json.dumps(resource_data, default=str)[:500] if resource_data else "unknown",
        error_code=None,
        provider="guardduty",
        severity=severity,
        description=_first(record.get("title"), record.get("description"), record.get("type"), default="GuardDuty finding"),
        raw=record,
    )


def normalize_securityhub(record: dict[str, Any]) -> NormalizedEvent:
    """Normalize an AWS Security Hub ASFF finding to the common event schema."""
    severity_block = record.get("Severity") or {}
    if not isinstance(severity_block, dict):
        severity_block = {}
    label = str(severity_block.get("Label") or "").upper()
    severity_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFORMATIONAL": 1.0}
    severity = severity_map.get(label)
    if severity is None:
        try:
            normalized = float(severity_block.get("Normalized"))
            severity = min(10.0, max(0.0, normalized / 10.0))
        except (TypeError, ValueError):
            severity = None

    resources = record.get("Resources") or []
    resource = "unknown"
    if isinstance(resources, list) and resources:
        first_resource = resources[0]
        if isinstance(first_resource, dict):
            resource = _first(first_resource.get("Id"), first_resource.get("Type"), default="unknown")
        elif first_resource is not None:
            resource = str(first_resource)

    resource_blob = record.get("Resources") or []
    principal = _deep_find(resource_blob, {"UserName", "PrincipalId", "PrincipalArn"})
    network = record.get("Network") or {}
    source_ip = _deep_find(network, {"SourceIpV4", "SourceIpV6", "SourceIpAddress"})
    if not source_ip:
        source_ip = _deep_find(record, {"SourceIpV4", "SourceIpV6", "IpAddressV4"})

    return NormalizedEvent(
        event_id=_first(record.get("Id"), record.get("id"), default=_stable_id(record)),
        event_time=_first(record.get("UpdatedAt"), record.get("CreatedAt"), record.get("FirstObservedAt"), default="unknown"),
        event_name="SecurityHubFinding",
        event_source=_first(record.get("ProductArn"), record.get("ProductName"), default="securityhub.amazonaws.com"),
        principal=str(principal) if principal else _first(record.get("AwsAccountId"), default="unknown"),
        source_ip=str(source_ip) if source_ip else "unknown",
        region=_first(record.get("Region")),
        resource=resource,
        error_code=None,
        provider="securityhub",
        severity=severity,
        description=_first(record.get("Title"), record.get("Description"), record.get("Types", [None])[0] if isinstance(record.get("Types"), list) and record.get("Types") else None, default="Security Hub finding"),
        raw=record,
    )


def _with_source(events: list[NormalizedEvent], filename: str) -> list[NormalizedEvent]:
    return [event.model_copy(update={"ingestion_source": "uploaded_file", "source_ref": filename}) for event in events]


def normalize_record(record: dict[str, Any]) -> NormalizedEvent:
    # AWS Security Finding Format (ASFF) records returned by Security Hub.
    if "ProductArn" in record and ("AwsAccountId" in record or "GeneratorId" in record) and ("Severity" in record or "FindingProviderFields" in record):
        return normalize_securityhub(record)
    if any(key in record for key in ("findingId", "type", "severity", "service")) and ("resource" in record or "service" in record):
        return normalize_guardduty(record)
    return normalize_cloudtrail(record)


def _records_from_json(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("Records", "records", "Findings", "findings", "events", "Events"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [data]
    raise ValueError("JSON input must be an object or an array of objects.")


def parse_log_content(filename: str, content: bytes) -> list[NormalizedEvent]:
    """Parse CloudTrail/GuardDuty/Security Hub JSON, JSONL, CSV, TXT, and gzip-compressed exports.

    Gzip content is decompressed with a hard cap to avoid accidentally expanding a
    malicious compressed upload into unbounded memory usage.
    """
    if not content:
        raise ValueError("The uploaded file is empty.")
    if filename.lower().endswith(".gz"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(content), mode="rb") as stream:
                content = stream.read(100 * 1024 * 1024 + 1)
        except (OSError, EOFError) as exc:
            raise ValueError("The .gz file is invalid or truncated.") from exc
        if len(content) > 100 * 1024 * 1024:
            raise ValueError("The decompressed .gz file exceeds the 100 MB parsing limit.")
        filename = filename[:-3]
    text = content.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise ValueError("The uploaded file contains no readable text.")
    extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

    if extension == "csv":
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(row) for row in reader]
        if not rows:
            raise ValueError("The CSV file has no data rows.")
        return _with_source([normalize_record(row) for row in rows], filename)

    try:
        data = json.loads(text)
        records = _records_from_json(data)
        if records:
            return _with_source([normalize_record(record) for record in records], filename)
    except json.JSONDecodeError:
        pass

    # Newline-delimited JSON is common for exported audit logs.
    jsonl_records: list[dict[str, Any]] = []
    jsonl_ok = True
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                jsonl_records.append(item)
            else:
                jsonl_ok = False
                break
        except json.JSONDecodeError:
            jsonl_ok = False
            break
    if jsonl_ok and jsonl_records:
        return _with_source([normalize_record(record) for record in jsonl_records], filename)

    # Generic text fallback preserves the raw line without inventing a timestamp.
    events: list[NormalizedEvent] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        timestamp_match = TIMESTAMP_RE.search(line)
        timestamp = timestamp_match.group(0) if timestamp_match else "unknown"
        raw = {"line_number": line_number, "message": line, "source_file": filename}
        events.append(NormalizedEvent(
            event_id=_stable_id(raw), event_time=timestamp, event_name="RawLogLine",
            event_source="uploaded-text", principal="unknown", source_ip="unknown",
            region="unknown", resource="unknown", provider="uploaded", description=line, raw=raw,
        ))
    if not events:
        raise ValueError("No readable events could be parsed from this file.")
    return events
