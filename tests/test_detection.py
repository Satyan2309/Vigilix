from app.config import SAMPLE_LOGS_DIR
from app.schemas import NormalizedEvent
from app.services.detection import analyze_events, classify_ip
from app.services.ingestion import parse_log_content


def _sample(name):
    return parse_log_content(name, (SAMPLE_LOGS_DIR / name).read_bytes())


def test_suspicious_sequence_generates_correlation_signals():
    events = _sample("cloudtrail_suspicious.json") + _sample("guardduty_findings.json")
    result = analyze_events(events)
    codes = {signal["code"] for signal in result["signals"]}
    assert "CORRELATED_CREDENTIAL_AND_PRIVILEGE_CHANGE" in codes
    assert "CORRELATED_PRIVILEGE_AND_LOGGING_CHANGE" in codes
    assert "FAILED_THEN_SUCCESSFUL_LOGIN" in codes
    assert result["risk_score"] >= 55
    assert result["severity"] in {"High", "Critical"}


def test_benign_sequence_does_not_trigger_high_risk_rules():
    events = _sample("cloudtrail_benign.json")
    result = analyze_events(events)
    assert result["risk_score"] < 30
    assert not any(signal["code"].startswith("CORRELATED_") for signal in result["signals"])


def test_root_account_usage_detection():
    event = NormalizedEvent(
        event_id="test-root-1",
        event_time="2026-03-01T12:00:00Z",
        event_name="CreateUser",
        principal="root",
        source_ip="203.0.113.5",
        raw={"userIdentity": {"type": "Root"}},
    )
    result = analyze_events([event])
    codes = {signal["code"] for signal in result["signals"]}
    assert "ROOT_ACCOUNT_ACTIVITY" in codes
    assert result["risk_score"] >= 45


def test_s3_public_exposure_detection():
    event = NormalizedEvent(
        event_id="test-s3-1",
        event_time="2026-03-01T12:05:00Z",
        event_name="PutBucketPolicy",
        principal="admin",
        source_ip="203.0.113.10",
        resource="arn:aws:s3:::confidential-data",
        raw={"requestParameters": {"bucketPolicy": '{"Statement":[{"Principal":"*","Effect":"Allow"}]}'}},
    )
    result = analyze_events([event])
    codes = {signal["code"] for signal in result["signals"]}
    assert "S3_PUBLIC_EXPOSURE_DETECTED" in codes


def test_security_group_open_to_world_detection():
    event = NormalizedEvent(
        event_id="test-sg-1",
        event_time="2026-03-01T12:10:00Z",
        event_name="AuthorizeSecurityGroupIngress",
        principal="infra-dev",
        source_ip="203.0.113.20",
        resource="sg-12345678",
        raw={"requestParameters": {"ipPermissions": [{"cidrIp": "0.0.0.0/0", "fromPort": 22, "toPort": 22}]}},
    )
    result = analyze_events([event])
    codes = {signal["code"] for signal in result["signals"]}
    assert "SECURITY_GROUP_OPEN_TO_WORLD" in codes


def test_kms_and_mfa_tampering_detection():
    kms_event = NormalizedEvent(
        event_id="test-kms-1",
        event_time="2026-03-01T12:15:00Z",
        event_name="ScheduleKeyDeletion",
        principal="sec-admin",
        source_ip="10.0.0.5",
        resource="arn:aws:kms:ap-south-1:123456789012:key/abc-123",
        raw={},
    )
    mfa_event = NormalizedEvent(
        event_id="test-mfa-1",
        event_time="2026-03-01T12:20:00Z",
        event_name="DeactivateMFADevice",
        principal="analyst-user",
        source_ip="10.0.0.5",
        raw={},
    )
    result = analyze_events([kms_event, mfa_event])
    codes = {signal["code"] for signal in result["signals"]}
    assert "KMS_KEY_TAMPERING_DETECTED" in codes
    assert "MFA_TAMPERING_DETECTED" in codes


def test_ip_classification_logic():
    assert classify_ip("10.0.1.5") == "private"
    assert classify_ip("192.168.1.1") == "private"
    assert classify_ip("203.0.113.15") == "documentation"
    assert classify_ip("198.51.100.2") == "documentation"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("s3.amazonaws.com") == "aws_service"
    assert classify_ip("8.8.8.8") == "external_public"
