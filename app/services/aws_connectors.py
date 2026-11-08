from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from app.schemas import NormalizedEvent
from app.services.ingestion import normalize_cloudtrail, normalize_guardduty, normalize_securityhub, parse_log_content


def _session(region: str, profile: str | None = None) -> boto3.Session:
    """Use the normal Boto3 credential chain; never accept credentials via the API."""
    profile_name = profile.strip() if profile and profile.strip() else None
    return boto3.Session(profile_name=profile_name, region_name=region)


def _tag(events: list[NormalizedEvent], source: str, source_ref: str | None = None) -> list[NormalizedEvent]:
    return [event.model_copy(update={"ingestion_source": source, "source_ref": source_ref}) for event in events]


def _read_cloudtrail_wrapper(wrapper: dict[str, Any], region: str, source: str) -> NormalizedEvent:
    raw = wrapper.get("CloudTrailEvent")
    if isinstance(raw, str):
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            record = {}
    else:
        record = raw if isinstance(raw, dict) else {}
    if not record:
        record = {
            "eventID": wrapper.get("EventId"),
            "eventTime": wrapper.get("EventTime").isoformat() if wrapper.get("EventTime") else "unknown",
            "eventName": wrapper.get("EventName"),
            "awsRegion": region,
            "userIdentity": {"userName": wrapper.get("Username")},
            "resources": wrapper.get("Resources", []),
            "eventSource": "cloudtrail.lookup_events",
        }
    record.setdefault("eventID", wrapper.get("EventId"))
    record.setdefault("eventTime", wrapper.get("EventTime").isoformat() if wrapper.get("EventTime") else "unknown")
    record.setdefault("eventName", wrapper.get("EventName"))
    record.setdefault("awsRegion", region)
    event = normalize_cloudtrail(record)
    return event.model_copy(update={"ingestion_source": source, "source_ref": f"cloudtrail:{region}"})


def sync_cloudtrail_events(
    region: str = "ap-south-1", hours: int = 24, limit: int = 200, profile: str | None = None
) -> list[NormalizedEvent]:
    """Read CloudTrail management-event history (up to AWS's 90-day Event History window)."""
    hours = max(1, min(int(hours), 2160))
    limit = max(1, min(int(limit), 1000))
    client = _session(region, profile).client("cloudtrail", region_name=region)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    events: list[NormalizedEvent] = []
    next_token = None
    while len(events) < limit:
        remaining = min(50, limit - len(events))
        kwargs: dict[str, Any] = {"StartTime": start_time, "EndTime": end_time, "MaxResults": remaining}
        if next_token:
            kwargs["NextToken"] = next_token
            # LookupEvents is limited to two requests per second per account and Region.
            time.sleep(0.55)
        response = client.lookup_events(**kwargs)
        events.extend(_read_cloudtrail_wrapper(wrapper, region, "aws_cloudtrail_api") for wrapper in response.get("Events", []))
        next_token = response.get("NextToken")
        if not next_token or not response.get("Events"):
            break
    return events[:limit]


def sync_cloudtrail_s3_logs(
    bucket: str,
    prefix: str = "",
    region: str = "ap-south-1",
    hours: int = 24,
    max_objects: int = 20,
    profile: str | None = None,
    max_scan: int = 10000,
) -> tuple[list[NormalizedEvent], dict[str, Any]]:
    """Read recently delivered CloudTrail JSON/JSON.GZ objects from a user-selected S3 bucket.

    With no prefix, use the standard AWSLogs/<account>/CloudTrail/<region>/ layout.
    A supplied prefix should point to the trail root; for example
    AWSLogs/123456789012/CloudTrail/ap-south-1/. For organization/custom paths,
    pass the exact account-specific trail root. A date folder may also be passed
    directly, but then only that folder is scanned.

    Requires s3:ListBucket for the bucket and s3:GetObject for matching log objects.
    This connector only reads; it never writes, deletes, or changes bucket settings.
    """
    bucket = bucket.strip()
    if not bucket:
        raise ValueError("An S3 bucket name is required.")
    if max_objects < 1 or max_objects > 100:
        raise ValueError("max_objects must be between 1 and 100.")
    hours = max(1, min(int(hours), 2160))
    max_scan = max(1, min(int(max_scan), 10000))
    session = _session(region, profile)
    s3 = session.client("s3", region_name=region)
    end_time = datetime.now(timezone.utc)
    since = end_time - timedelta(hours=hours)

    requested_prefix = prefix.strip().strip("/")
    date_folder_pattern = re.compile(r"(?:^|/)\d{4}/\d{2}/\d{2}$")
    if requested_prefix and date_folder_pattern.search(requested_prefix):
        day_prefixes = [requested_prefix + "/"]
    else:
        if requested_prefix:
            root_prefix = requested_prefix + "/"
        else:
            account = session.client("sts", region_name=region).get_caller_identity().get("Account")
            if not account:
                raise RuntimeError("Could not determine the AWS account ID for the standard CloudTrail S3 prefix. Supply a prefix explicitly.")
            root_prefix = f"AWSLogs/{account}/CloudTrail/{region}/"
        day_prefixes = []
        cursor = since.date()
        while cursor <= end_time.date():
            day_prefixes.append(root_prefix + cursor.strftime("%Y/%m/%d") + "/")
            cursor += timedelta(days=1)

    candidates_by_key: dict[str, dict[str, Any]] = {}
    scanned = 0
    paginator = s3.get_paginator("list_objects_v2")
    scan_limit_reached = False
    for day_prefix in day_prefixes:
        for page in paginator.paginate(Bucket=bucket, Prefix=day_prefix):
            for obj in page.get("Contents", []):
                scanned += 1
                key = str(obj.get("Key", ""))
                modified = obj.get("LastModified")
                if key.lower().endswith((".json", ".json.gz")) and modified and modified >= since:
                    candidates_by_key[key] = obj
                if scanned >= max_scan:
                    scan_limit_reached = True
                    break
            if scan_limit_reached:
                break
        if scan_limit_reached:
            break

    candidates = sorted(
        candidates_by_key.values(),
        key=lambda obj: obj.get("LastModified") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    matching_recent_objects = len(candidates)
    candidates = candidates[:max_objects]
    events: list[NormalizedEvent] = []
    skipped_objects: list[str] = []
    processed_objects = 0
    for obj in candidates:
        key = str(obj["Key"])
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"].read(25 * 1024 * 1024 + 1)
        if len(body) > 25 * 1024 * 1024:
            skipped_objects.append(f"{key} (object size exceeded 25 MB cap)")
            continue
        try:
            parsed = parse_log_content(key.rsplit("/", 1)[-1], body)
        except (ValueError, OSError) as exc:
            skipped_objects.append(f"{key} ({str(exc)[:100]})")
            continue
        processed_objects += 1
        for event in parsed:
            if event.provider != "aws":
                continue
            # Keep events inside the requested window, even when an object contains
            # records spanning multiple event times. Unknown timestamps are retained
            # because the file itself matched the recent delivery window.
            parsed_time = None
            try:
                parsed_time = datetime.fromisoformat(event.event_time.replace("Z", "+00:00"))
                if parsed_time.tzinfo is None:
                    parsed_time = parsed_time.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError, AttributeError):
                pass
            if parsed_time is not None and not (since <= parsed_time.astimezone(timezone.utc) <= end_time):
                continue
            events.append(event.model_copy(update={
                "ingestion_source": "aws_s3_cloudtrail",
                "source_ref": f"s3://{bucket}/{key}",
            }))

    metadata = {
        "scanned_objects": scanned,
        "matching_recent_objects": matching_recent_objects,
        "processed_objects": processed_objects,
        "skipped_objects": len(skipped_objects),
        "skipped_examples": skipped_objects[:5],
        "scan_limit_reached": scan_limit_reached,
        "prefixes_scanned": day_prefixes,
    }
    return events, metadata


def sync_guardduty_findings(
    region: str = "ap-south-1", limit: int = 50, profile: str | None = None
) -> list[NormalizedEvent]:
    """Read existing GuardDuty findings; this connector never enables/configures GuardDuty."""
    limit = max(1, min(int(limit), 100))
    client = _session(region, profile).client("guardduty", region_name=region)
    detectors = client.list_detectors().get("DetectorIds", [])
    if not detectors:
        raise RuntimeError(f"No GuardDuty detector found in region {region}. This connector does not create or enable one.")
    detector_id = detectors[0]
    finding_ids: list[str] = []
    next_token = None
    while len(finding_ids) < limit:
        kwargs: dict[str, Any] = {
            "DetectorId": detector_id,
            "MaxResults": min(50, limit - len(finding_ids)),
            "SortCriteria": {"AttributeName": "updatedAt", "OrderBy": "DESC"},
        }
        if next_token:
            kwargs["NextToken"] = next_token
        response = client.list_findings(**kwargs)
        finding_ids.extend(response.get("FindingIds", []))
        next_token = response.get("NextToken")
        if not next_token or not response.get("FindingIds"):
            break
    finding_ids = finding_ids[:limit]
    findings: list[dict[str, Any]] = []
    for start in range(0, len(finding_ids), 50):
        details = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids[start:start + 50])
        findings.extend(details.get("Findings", []))
    events = [normalize_guardduty(finding) for finding in findings]
    return _tag(events, "aws_guardduty_api", f"guardduty:{region}")


def sync_securityhub_findings(
    region: str = "ap-south-1", limit: int = 100, profile: str | None = None
) -> list[NormalizedEvent]:
    """Read existing active Security Hub findings; this connector never enables Security Hub."""
    limit = max(1, min(int(limit), 100))
    client = _session(region, profile).client("securityhub", region_name=region)
    findings: list[dict[str, Any]] = []
    next_token = None
    while len(findings) < limit:
        kwargs: dict[str, Any] = {
            "MaxResults": min(100, limit - len(findings)),
            "Filters": {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
            "SortCriteria": [{"Field": "UpdatedAt", "SortOrder": "desc"}],
        }
        if next_token:
            kwargs["NextToken"] = next_token
        response = client.get_findings(**kwargs)
        findings.extend(response.get("Findings", []))
        next_token = response.get("NextToken")
        if not next_token or not response.get("Findings"):
            break
    events = [normalize_securityhub(finding) for finding in findings[:limit]]
    return _tag(events, "aws_securityhub_api", f"securityhub:{region}")


def get_aws_status(region: str = "ap-south-1", profile: str | None = None) -> dict[str, Any]:
    """Probe AWS identity and optional service read-access without changing resources."""
    session = _session(region, profile)
    sts = session.client("sts", region_name=region)
    identity = sts.get_caller_identity()
    account = str(identity.get("Account", ""))
    masked_account = f"{account[:4]}{'*' * max(0, len(account) - 8)}{account[-4:]}" if len(account) >= 8 else account
    arn = str(identity.get("Arn", ""))
    # Keep the account ID masked in API status responses as well as the UI.
    if len(account) == 12:
        arn = arn.replace(f"::{account}:", "::************:")
    statuses: dict[str, dict[str, Any]] = {}

    def check(name: str, action) -> None:
        try:
            value = action()
            statuses[name] = {"status": "available", "detail": value}
        except Exception as exc:
            statuses[name] = {"status": "unavailable", "detail": aws_error_message(exc)}

    def check_cloudtrail() -> str:
        result = session.client("cloudtrail", region_name=region).lookup_events(
            StartTime=datetime.now(timezone.utc) - timedelta(hours=1),
            EndTime=datetime.now(timezone.utc), MaxResults=1,
        )
        return f"Read access confirmed; up to {len(result.get('Events', []))} sample event returned."

    def check_guardduty() -> str:
        values = session.client("guardduty", region_name=region).list_detectors().get("DetectorIds", [])
        if not values:
            raise RuntimeError("No GuardDuty detector is enabled in this Region.")
        return f"{len(values)} detector(s) available; sync only reads findings."

    def check_securityhub() -> str:
        session.client("securityhub", region_name=region).describe_hub()
        return "Security Hub is enabled and the current identity can describe the hub."

    check("cloudtrail", check_cloudtrail)
    check("guardduty", check_guardduty)
    check("securityhub", check_securityhub)
    return {
        "connected": True,
        "region": region,
        "account_id_masked": masked_account,
        "caller_arn": arn,
        "profile": profile or "default credential chain",
        "services": statuses,
        "note": "Read-only connection checks only; no services, trails, detectors, or findings were configured or modified.",
    }


def aws_error_message(exc: Exception) -> str:
    if isinstance(exc, NoCredentialsError):
        return "AWS credentials were not found. Configure an AWS CLI profile/SSO session or use uploaded logs."
    if isinstance(exc, ProfileNotFound):
        return "The configured AWS profile was not found. Check your AWS CLI profile configuration."
    if isinstance(exc, ClientError):
        error = exc.response.get("Error", {})
        code = error.get("Code", "AWSClientError")
        message = error.get("Message", "AWS request failed")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "InvalidAccessException"}:
            return f"AWS denied the read request ({code}). Verify the region, service enablement, and read-only IAM permissions."
        if code in {"ResourceNotFoundException", "DetectorNotFoundException"}:
            return f"AWS resource/service was not found ({code}): {message[:180]}"
        return f"AWS request failed ({code}): {message[:250]}"
    if isinstance(exc, BotoCoreError):
        return f"AWS SDK connection/configuration error: {str(exc)[:250]}"
    return str(exc)[:350]
