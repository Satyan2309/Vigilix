from __future__ import annotations

from app.services import public_datasets


def test_public_dataset_import_adds_provenance_and_normalizes_flattened_csv(monkeypatch):
    csv_bytes = (
        "eventTime,eventSource,eventName,awsRegion,sourceIPAddress,eventID,userIdentity.arn,errorCode\n"
        "2026-01-26T03:33:00Z,sts.amazonaws.com,AssumeRole,us-east-1,203.0.113.42,e-1,arn:aws:iam::000000000000:user/operator,AccessDenied\n"
        "2026-01-26T03:34:00Z,cloudtrail.amazonaws.com,StopLogging,us-east-1,203.0.113.42,e-2,arn:aws:iam::000000000000:user/operator,AccessDenied\n"
    ).encode("utf-8")
    monkeypatch.setattr(
        public_datasets, "_download_dataset",
        lambda: (csv_bytes, {"sha256": "test-hash", "license": "MIT", "source": public_datasets.DATASET_BLOB_URL}),
    )
    monkeypatch.setattr(public_datasets, "DATASET_PATH", public_datasets.ROOT_DIR / "data" / "does-not-exist.csv")

    events, metadata = public_datasets.load_public_cloudtrail_dataset(max_events=2)

    assert len(events) == 2
    assert events[0].event_name == "AssumeRole"
    assert events[0].principal.endswith("operator")
    assert events[0].source_ip == "203.0.113.42"
    assert events[0].ingestion_source == "public_anonymized_cloudtrail"
    assert events[0].source_ref == public_datasets.DATASET_BLOB_URL
    assert metadata["anonymized_public_research_data"] is True
    assert metadata["total_records_in_file"] == 2


def test_public_dataset_rejects_unsafe_record_limit():
    try:
        public_datasets.load_public_cloudtrail_dataset(max_events=100_000)
        assert False, "Expected a limit validation error"
    except public_datasets.PublicDatasetError as exc:
        assert "max_events" in str(exc)


def test_public_dataset_shape_drives_documented_incident_detection(monkeypatch):
    from app.services.detection import analyze_events

    csv_bytes = (
        "eventtime,eventsource,eventname,awsregion,sourceipaddress,errorcode,readonly\n"
        "2026-01-26 03:31:20+00:00,sts.amazonaws.com,AssumeRole,us-east-1,203.0.113.42,AccessDenied,False\n"
        "2026-01-26 03:32:10+00:00,cloudtrail.amazonaws.com,StopLogging,us-east-1,203.0.113.42,AccessDenied,False\n"
        "2026-01-26 03:33:00+00:00,cloudtrail.amazonaws.com,DeleteTrail,us-east-1,203.0.113.42,AccessDenied,False\n"
        "2026-01-26 12:00:00+00:00,ec2.amazonaws.com,DescribeInstances,us-east-1,203.0.113.42,,True\n"
    ).encode("utf-8")
    monkeypatch.setattr(
        public_datasets, "_download_dataset",
        lambda: (csv_bytes, {"sha256": "sample-hash", "license": "MIT", "source": public_datasets.DATASET_BLOB_URL}),
    )
    monkeypatch.setattr(public_datasets, "DATASET_PATH", public_datasets.ROOT_DIR / "data" / "public-dataset-not-cached.csv")

    events, metadata = public_datasets.load_public_cloudtrail_dataset(max_events=3)
    result = analyze_events(events)

    assert metadata["total_records_in_file"] == 4
    assert len(events) == 3
    assert all(event.ingestion_source == "public_anonymized_cloudtrail" for event in events)
    assert any(signal["code"] == "DENIED_ROLE_ASSUMPTION_BEFORE_AUDIT_LOG_TAMPERING" for signal in result["signals"])
    assert result["severity"] == "Critical"
