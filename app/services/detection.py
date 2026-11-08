from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.schemas import NormalizedEvent

PRIVILEGE_EVENTS = {
    "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion", "UpdateAssumeRolePolicy",
    "AddUserToGroup", "CreateLoginProfile", "UpdateLoginProfile",
}
CREDENTIAL_EVENTS = {"CreateAccessKey", "CreateLoginProfile", "CreateServiceSpecificCredential", "CreateSshPublicKey"}
LOGGING_EVENTS = {"StopLogging", "DeleteTrail", "PutEventSelectors", "UpdateTrail"}
OTHER_HIGH_RISK_EVENTS = {"PutBucketPolicy", "DeleteBucketPolicy", "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupEgress", "DeleteFlowLogs"}
ROLE_ASSUMPTION_EVENTS = {"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"}
KMS_TAMPER_EVENTS = {"DisableKey", "ScheduleKeyDeletion", "DisableKeyRotation"}
MFA_TAMPER_EVENTS = {"DeactivateMFADevice", "DeleteVirtualMFADevice"}
PASSWORD_POLICY_EVENTS = {"UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"}

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


def parse_time(value: str) -> datetime | None:
    if not value or value == "unknown":
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def classify_ip(ip_str: str) -> str:
    """Classify IP as private, documentation, aws_service, loopback, or external_public."""
    if not ip_str or ip_str in ("unknown", "None", ""):
        return "unknown"
    if "amazonaws.com" in ip_str.lower() or ip_str.lower().startswith("aws-"):
        return "aws_service"
    try:
        ip = ipaddress.ip_address(ip_str.split(":")[0])
        if ip.is_loopback:
            return "loopback"
        # RFC 5737 documentation test nets (check before is_private since Python treats them as private)
        if (
            ip in ipaddress.ip_network("192.0.2.0/24")
            or ip in ipaddress.ip_network("198.51.100.0/24")
            or ip in ipaddress.ip_network("203.0.113.0/24")
        ):
            return "documentation"
        if ip.is_private:
            return "private"
        return "external_public"
    except ValueError:
        return "external_public" if "." in ip_str or ":" in ip_str else "internal_identifier"


def _login_result(event: NormalizedEvent) -> str:
    if event.error_code:
        return "failure"
    response = event.raw.get("responseElements") or {}
    if isinstance(response, dict):
        console_login = response.get("ConsoleLogin") or response.get("consoleLogin")
        if isinstance(console_login, str):
            return "success" if console_login.lower() == "success" else "failure"
    description = (event.description or "").lower()
    if "failed" in description or "failure" in description or "unsuccessful" in description:
        return "failure"
    return "success"


def _check_s3_public_exposure(event: NormalizedEvent) -> tuple[bool, str]:
    if event.event_name not in {"PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock"}:
        return False, ""
    if event.event_name == "DeletePublicAccessBlock":
        return True, "S3 Public Access Block was deleted, potentially exposing bucket to public access."
    raw_str = json.dumps(event.raw, default=str)
    if (
        '"Principal":"*"' in raw_str
        or '"Principal": "*"' in raw_str
        or '\"Principal\":\"*\"' in raw_str
        or '\"Principal\": \"*\"' in raw_str
        or "AllUsers" in raw_str
        or ("Effect" in raw_str and "Allow" in raw_str and "Principal" in raw_str and "*" in raw_str)
    ):
        return True, f"Bucket policy/ACL change ({event.event_name}) contains wildcard or public allowance."
    return False, ""


def _check_security_group_open(event: NormalizedEvent) -> tuple[bool, str]:
    if event.event_name != "AuthorizeSecurityGroupIngress":
        return False, ""
    raw_str = json.dumps(event.raw, default=str)
    if "0.0.0.0/0" in raw_str or "::/0" in raw_str:
        exposed = []
        for port, name in SENSITIVE_PORTS.items():
            if f'"fromPort":{port}' in raw_str or f'"toPort":{port}' in raw_str or f'"fromPort": {port}' in raw_str or f'"toPort": {port}' in raw_str:
                exposed.append(f"{name} ({port})")
        if exposed:
            return True, f"Security group ingress opened to 0.0.0.0/0 on sensitive port(s): {', '.join(exposed)}."
        return True, "Security group ingress opened to entire internet (0.0.0.0/0)."
    return False, ""


def _is_root_principal(event: NormalizedEvent) -> bool:
    if event.principal.lower() in {"root", "arn:aws:iam::root"}:
        return True
    user_identity = event.raw.get("userIdentity")
    if isinstance(user_identity, dict) and user_identity.get("type") == "Root":
        return True
    return False


def _event_weight(event: NormalizedEvent) -> tuple[int, str | None]:
    name = event.event_name
    if name in {"GuardDutyFinding", "SecurityHubFinding"}:
        sev = event.severity or 0
        source_label = "GuardDuty" if name == "GuardDutyFinding" else "Security Hub"
        if sev >= 9:
            return 65, f"Critical {source_label} finding"
        if sev >= 7:
            return 55, f"High-severity {source_label} finding"
        if sev >= 4:
            return 35, f"Medium-severity {source_label} finding"
        if sev > 0:
            return 18, f"Low-severity {source_label} finding"
    if name in LOGGING_EVENTS:
        if name in {"StopLogging", "DeleteTrail"}:
            return 55, f"Audit-logging operation: {name}"
        return 30, f"CloudTrail configuration changed: {name}"
    if name in PRIVILEGE_EVENTS:
        return 42, f"Privilege or identity configuration operation: {name}"
    if name in CREDENTIAL_EVENTS:
        return 28, f"Credential creation operation: {name}"
    if name in KMS_TAMPER_EVENTS:
        return 50, f"KMS key tampering operation: {name}"
    if name in MFA_TAMPER_EVENTS:
        return 48, f"MFA security control deactivation: {name}"
    if name in PASSWORD_POLICY_EVENTS:
        return 38, f"Password policy modified or deleted: {name}"
    if name in OTHER_HIGH_RISK_EVENTS:
        return 36, f"Potentially high-impact cloud configuration operation: {name}"
    if name in ROLE_ASSUMPTION_EVENTS and event.error_code:
        return 12, f"Denied role-assumption attempt: {name}"
    if name == "ConsoleLogin" and _login_result(event) == "failure":
        return 8, "Failed console sign-in"
    return 0, None


def analyze_events(events: list[NormalizedEvent]) -> dict[str, Any]:
    """Run deterministic, explainable triage and correlation rules over normalized events."""
    signals: list[dict[str, Any]] = []
    score_candidates: list[int] = []
    weighted_events: list[tuple[NormalizedEvent, int]] = []
    ip_classification_map: dict[str, str] = {}

    for event in events:
        if event.source_ip not in ("", "unknown", None) and event.source_ip not in ip_classification_map:
            ip_classification_map[event.source_ip] = classify_ip(event.source_ip)

        # 1. Root account usage check (CIS Benchmark 1.1)
        if _is_root_principal(event):
            signals.append({
                "code": "ROOT_ACCOUNT_ACTIVITY",
                "title": f"Root account activity observed ({event.event_name})",
                "severity": "high",
                "description": f"Root account principal performed {event.event_name} at {event.event_time}. CIS benchmark recommends avoiding the root user for routine administrative tasks.",
                "event_ids": [event.event_id],
            })
            score_candidates.append(50)

        # 2. S3 public exposure check
        s3_exposed, s3_detail = _check_s3_public_exposure(event)
        if s3_exposed:
            signals.append({
                "code": "S3_PUBLIC_EXPOSURE_DETECTED",
                "title": "S3 bucket policy or public access tampering",
                "severity": "high",
                "description": s3_detail,
                "event_ids": [event.event_id],
            })
            score_candidates.append(52)

        # 3. Security group open to world check
        sg_exposed, sg_detail = _check_security_group_open(event)
        if sg_exposed:
            signals.append({
                "code": "SECURITY_GROUP_OPEN_TO_WORLD",
                "title": "Security group opened to 0.0.0.0/0",
                "severity": "high",
                "description": sg_detail,
                "event_ids": [event.event_id],
            })
            score_candidates.append(50)

        # 4. KMS Key Tampering Check
        if event.event_name in KMS_TAMPER_EVENTS:
            signals.append({
                "code": "KMS_KEY_TAMPERING_DETECTED",
                "title": f"KMS key disabled or scheduled for deletion ({event.event_name})",
                "severity": "high",
                "description": f"Operation {event.event_name} on KMS key {event.resource}. Disabling or deleting keys can deny access to encrypted backups or services.",
                "event_ids": [event.event_id],
            })
            score_candidates.append(48)

        # 5. MFA Deactivation Check
        if event.event_name in MFA_TAMPER_EVENTS:
            signals.append({
                "code": "MFA_TAMPERING_DETECTED",
                "title": f"MFA security device deactivated ({event.event_name})",
                "severity": "high",
                "description": f"MFA device was deactivated or deleted for {event.principal}. Verify if this was part of an approved hardware replacement.",
                "event_ids": [event.event_id],
            })
            score_candidates.append(45)

        # Baseline event weight
        weight, explanation = _event_weight(event)
        if weight:
            weighted_events.append((event, weight))
            score_candidates.append(weight)
            signals.append({
                "code": f"EVENT_{event.event_name.upper()}",
                "title": explanation or event.event_name,
                "severity": "high" if weight >= 40 else "medium" if weight >= 25 else "low",
                "description": f"Observed {event.event_name} at {event.event_time}; principal={event.principal}; source_ip={event.source_ip}.",
                "event_ids": [event.event_id],
            })

    # Group by principal for sequence correlation
    known_principals = [e for e in events if e.principal not in ("", "unknown", None)]
    by_principal: dict[str, list[NormalizedEvent]] = {}
    for event in known_principals:
        by_principal.setdefault(event.principal, []).append(event)

    for principal, group in by_principal.items():
        timed = [(event, parse_time(event.event_time)) for event in group]
        timed = [(event, dt) for event, dt in timed if dt is not None]
        timed.sort(key=lambda pair: pair[1])
        names = {event.event_name for event, _ in timed}

        if names & CREDENTIAL_EVENTS and names & PRIVILEGE_EVENTS:
            pair = _find_sequence(timed, CREDENTIAL_EVENTS, PRIVILEGE_EVENTS, 60)
            if pair:
                e1, e2 = pair
                signals.append({
                    "code": "CORRELATED_CREDENTIAL_AND_PRIVILEGE_CHANGE",
                    "title": "Credential creation followed by privilege change",
                    "severity": "high",
                    "description": "The same principal created credentials and then performed a privilege-related operation within 60 minutes. Verify whether both actions were authorized.",
                    "event_ids": [e1.event_id, e2.event_id],
                })
                score_candidates.append(25)

        if names & PRIVILEGE_EVENTS and names & LOGGING_EVENTS:
            pair = _find_sequence(timed, PRIVILEGE_EVENTS, LOGGING_EVENTS, 60)
            if pair:
                e1, e2 = pair
                signals.append({
                    "code": "CORRELATED_PRIVILEGE_AND_LOGGING_CHANGE",
                    "title": "Privilege change correlated with audit-logging change",
                    "severity": "critical",
                    "description": "The same principal performed a privilege-related operation and changed audit-logging configuration within 60 minutes. This sequence warrants prompt validation.",
                    "event_ids": [e1.event_id, e2.event_id],
                })
                score_candidates.append(32)

        login_events = [(event, dt) for event, dt in timed if event.event_name == "ConsoleLogin"]
        failures = [(event, dt) for event, dt in login_events if _login_result(event) == "failure"]
        successes = [(event, dt) for event, dt in login_events if _login_result(event) == "success"]
        correlated_login = None
        for fail, fail_dt in failures:
            for success, success_dt in successes:
                same_ip = fail.source_ip == success.source_ip or "unknown" in (fail.source_ip, success.source_ip)
                within_window = 0 <= (success_dt - fail_dt).total_seconds() <= 10 * 60
                if same_ip and within_window:
                    correlated_login = (fail, success)
                    break
            if correlated_login:
                break
        if correlated_login:
            fail, success = correlated_login
            signals.append({
                "code": "FAILED_THEN_SUCCESSFUL_LOGIN",
                "title": "Failed sign-in activity followed by a successful sign-in",
                "severity": "medium",
                "description": "Failed console sign-in activity was followed by a successful sign-in for the same principal within ten minutes. This can be legitimate; validate source, MFA, and user context.",
                "event_ids": [fail.event_id, success.event_id],
            })
            score_candidates.append(18)

    # Correlate denied role assumption followed by audit-log tampering using source IP
    by_source_ip: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        if event.source_ip not in ("", "unknown", None):
            by_source_ip.setdefault(event.source_ip, []).append(event)
    emitted_sequences: set[tuple[str, str]] = set()
    for source_ip, group in by_source_ip.items():
        timed_by_ip = [(event, parse_time(event.event_time)) for event in group]
        timed_by_ip = [(event, dt) for event, dt in timed_by_ip if dt is not None]
        timed_by_ip.sort(key=lambda pair: pair[1])
        denied_roles = [(event, dt) for event, dt in timed_by_ip if event.event_name in ROLE_ASSUMPTION_EVENTS and event.error_code]
        logging_tamper = [(event, dt) for event, dt in timed_by_ip if event.event_name in {"StopLogging", "DeleteTrail"}]
        for role_event, role_dt in denied_roles:
            for logging_event, logging_dt in logging_tamper:
                delta = (logging_dt - role_dt).total_seconds()
                pair_key = (role_event.event_id, logging_event.event_id)
                if 0 <= delta <= 5 * 60 and pair_key not in emitted_sequences:
                    emitted_sequences.add(pair_key)
                    signals.append({
                        "code": "DENIED_ROLE_ASSUMPTION_BEFORE_AUDIT_LOG_TAMPERING",
                        "title": "Denied role assumption followed by audit-logging tampering attempt",
                        "severity": "critical",
                        "description": (
                            f"A denied role-assumption event was followed by {logging_event.event_name} "
                            f"within five minutes from the same source IP ({source_ip}). Validate the actor, surrounding events, and authorization context."
                        ),
                        "event_ids": [role_event.event_id, logging_event.event_id],
                    })
                    score_candidates.append(90)

    # External IP check for high-impact operations
    for event in events:
        ip_type = ip_classification_map.get(event.source_ip, "unknown")
        if ip_type == "external_public" and (event.event_name in PRIVILEGE_EVENTS or event.event_name in LOGGING_EVENTS):
            signals.append({
                "code": "EXTERNAL_IP_ADMIN_ACTIVITY",
                "title": f"High-privilege operation from external public IP ({event.source_ip})",
                "severity": "medium",
                "description": f"Principal {event.principal} performed {event.event_name} from an external public IP address ({event.source_ip}). Verify if the administrator was on a sanctioned VPN or network.",
                "event_ids": [event.event_id],
            })
            score_candidates.append(22)
            break

    # Calculate overall risk score
    score = min(
        100,
        (max(score_candidates) if score_candidates else 5)
        + max(0, sum(1 for s in signals if s["code"].startswith("CORRELATED_") or s["code"] == "FAILED_THEN_SUCCESSFUL_LOGIN") * 12)
    )
    if score >= 85:
        severity = "Critical"
    elif score >= 55:
        severity = "High"
    elif score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    timeline = []
    for event in sorted(events, key=lambda e: (parse_time(e.event_time) is None, parse_time(e.event_time) or datetime.max.replace(tzinfo=timezone.utc))):
        timeline.append({
            "event_id": event.event_id,
            "event_time": event.event_time,
            "event_name": event.event_name,
            "principal": event.principal,
            "source_ip": event.source_ip,
            "ip_classification": ip_classification_map.get(event.source_ip, "unknown"),
            "region": event.region,
            "resource": event.resource,
            "provider": event.provider,
        })

    unique_principals = sorted({e.principal for e in events if e.principal != "unknown"})
    unique_ips = sorted({e.source_ip for e in events if e.source_ip != "unknown"})
    return {
        "risk_score": score,
        "severity": severity,
        "signals": signals,
        "timeline": timeline,
        "event_count": len(events),
        "principal_count": len(unique_principals),
        "source_ips": unique_ips,
        "principals": unique_principals,
        "ip_classification": ip_classification_map,
        "observed_event_names": sorted({e.event_name for e in events}),
    }


def _find_sequence(
    timed: list[tuple[NormalizedEvent, datetime]],
    first_names: set[str],
    second_names: set[str],
    minutes: int,
) -> tuple[NormalizedEvent, NormalizedEvent] | None:
    for first_event, first_dt in timed:
        if first_event.event_name not in first_names:
            continue
        for second_event, second_dt in timed:
            if second_event.event_name not in second_names:
                continue
            delta = (second_dt - first_dt).total_seconds()
            if 0 <= delta <= minutes * 60:
                return first_event, second_event
    return None
