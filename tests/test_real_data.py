import gzip
import json

from app.services.detection import analyze_events
from app.services.ingestion import parse_log_content


def test_parse_gzip_compressed_real_cloudtrail_shape():
    record = {
        "eventVersion": "1.08",
        "eventTime": "2026-10-27T08:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": "203.0.113.8",
        "userIdentity": {"type": "IAMUser", "userName": "test-operator", "principalId": "AIDAEXAMPLE"},
        "eventID": "real-format-event-001",
        "requestParameters": {"userName": "application-user"},
        "responseElements": {"accessKey": {"status": "Active"}},
    }
    payload = gzip.compress(json.dumps({"Records": [record]}).encode("utf-8"))
    events = parse_log_content("123456789012_CloudTrail_ap-south-1_20261027T0800Z_example.json.gz", payload)
    assert len(events) == 1
    assert events[0].event_id == "real-format-event-001"
    assert events[0].event_name == "CreateAccessKey"
    assert events[0].principal == "test-operator"
    assert events[0].ingestion_source == "uploaded_file"
    assert events[0].provider == "aws"


def test_parse_security_hub_asff_finding():
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": "arn:aws:securityhub:ap-south-1:123456789012:subscription/example/finding/example-id",
        "ProductArn": "arn:aws:securityhub:ap-south-1::product/aws/securityhub",
        "GeneratorId": "security-control/CloudTrail.1",
        "AwsAccountId": "123456789012",
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices"],
        "CreatedAt": "2026-10-27T08:00:00Z",
        "UpdatedAt": "2026-10-27T08:05:00Z",
        "Title": "CloudTrail should be enabled",
        "Description": "CloudTrail trail logging should be enabled.",
        "Resources": [{"Type": "AwsAccount", "Id": "123456789012"}],
        "Severity": {"Label": "HIGH", "Normalized": 75.0},
        "RecordState": "ACTIVE",
    }
    events = parse_log_content("securityhub.json", json.dumps({"Findings": [finding]}).encode())
    assert len(events) == 1
    assert events[0].provider == "securityhub"
    assert events[0].event_name == "SecurityHubFinding"
    assert events[0].severity == 7.5
    result = analyze_events(events)
    assert any("Security Hub" in signal["title"] for signal in result["signals"])


def test_upload_provenance_is_retained_for_jsonl():
    content = b'{"eventTime":"2026-10-27T08:00:00Z","eventName":"ListBuckets","eventID":"e1"}\n'
    event = parse_log_content("audit.jsonl", content)[0]
    assert event.ingestion_source == "uploaded_file"
    assert event.source_ref == "audit.jsonl"


def test_correlates_anonymized_public_cloudtrail_sequence_by_source_ip():
    from app.schemas import NormalizedEvent

    events = [
        NormalizedEvent(
            event_id="role-denied", event_time="2026-01-26T03:33:00Z",
            event_name="AssumeRole", event_source="sts.amazonaws.com", principal="unknown",
            source_ip="203.0.113.42", error_code="AccessDenied", provider="aws",
            ingestion_source="public_anonymized_cloudtrail",
        ),
        NormalizedEvent(
            event_id="stop-logging", event_time="2026-01-26T03:34:00Z",
            event_name="StopLogging", event_source="cloudtrail.amazonaws.com", principal="unknown",
            source_ip="203.0.113.42", error_code="AccessDenied", provider="aws",
            ingestion_source="public_anonymized_cloudtrail",
        ),
        NormalizedEvent(
            event_id="delete-trail", event_time="2026-01-26T03:35:00Z",
            event_name="DeleteTrail", event_source="cloudtrail.amazonaws.com", principal="unknown",
            source_ip="203.0.113.42", error_code="AccessDenied", provider="aws",
            ingestion_source="public_anonymized_cloudtrail",
        ),
    ]
    result = analyze_events(events)
    assert any(signal["code"] == "DENIED_ROLE_ASSUMPTION_BEFORE_AUDIT_LOG_TAMPERING" for signal in result["signals"])
    assert result["severity"] == "Critical"


def test_parse_lowercase_anonymized_research_csv_columns():
    csv_content = (
        "eventtime,eventsource,eventname,awsregion,sourceipaddress,errorcode,readonly\n"
        "2026-01-26 03:31:00+00:00,sts.amazonaws.com,AssumeRole,us-east-1,203.0.113.42,AccessDenied,False\n"
    ).encode("utf-8")
    events = parse_log_content("dataset.csv", csv_content)
    assert len(events) == 1
    assert events[0].event_time == "2026-01-26T03:31:00+00:00"
    assert events[0].event_name == "AssumeRole"
    assert events[0].event_source == "sts.amazonaws.com"
    assert events[0].source_ip == "203.0.113.42"
    assert events[0].error_code == "AccessDenied"
