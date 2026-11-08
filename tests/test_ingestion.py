from pathlib import Path

from app.config import SAMPLE_LOGS_DIR
from app.services.ingestion import parse_log_content


def test_parse_cloudtrail_sample():
    events = parse_log_content("cloudtrail_suspicious.json", (SAMPLE_LOGS_DIR / "cloudtrail_suspicious.json").read_bytes())
    assert len(events) == 5
    assert events[0].event_name == "ConsoleLogin"
    assert events[2].event_name == "CreateAccessKey"
    assert events[2].principal.endswith("analyst-demo")


def test_parse_guardduty_sample():
    events = parse_log_content("guardduty_findings.json", (SAMPLE_LOGS_DIR / "guardduty_findings.json").read_bytes())
    assert len(events) == 1
    assert events[0].provider == "guardduty"
    assert events[0].event_name == "GuardDutyFinding"
    assert events[0].severity == 8.0


def test_parse_jsonl_and_csv():
    jsonl = b'{"eventTime":"2026-01-01T00:00:00Z","eventName":"DescribeInstances","eventID":"one"}\n{"eventTime":"2026-01-01T00:01:00Z","eventName":"ListBuckets","eventID":"two"}'
    assert len(parse_log_content("events.jsonl", jsonl)) == 2
    csv_bytes = b'eventTime,eventName,eventID\n2026-01-01T00:00:00Z,DescribeInstances,csv-one\n'
    assert parse_log_content("events.csv", csv_bytes)[0].event_name == "DescribeInstances"
