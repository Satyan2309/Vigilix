import gzip
import io
import json
from datetime import datetime, timezone

from app.services import aws_connectors


class _FakePaginator:
    def __init__(self, objects):
        self.objects = objects

    def paginate(self, **kwargs):
        prefix = kwargs.get("Prefix", "")
        rows = [row for row in self.objects if row["Key"].startswith(prefix)]
        yield {"Contents": rows}


class _FakeS3:
    def __init__(self, objects, bodies):
        self.objects = objects
        self.bodies = bodies

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _FakePaginator(self.objects)

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.bodies[Key])}


class _FakeSession:
    def __init__(self, s3):
        self.s3 = s3

    def client(self, service, region_name=None):
        assert service == "s3"
        return self.s3


def test_s3_cloudtrail_sync_reads_recent_gzip_and_tracks_source(monkeypatch):
    now = datetime.now(timezone.utc)
    day = now.strftime("%Y/%m/%d")
    root_prefix = "AWSLogs/123456789012/CloudTrail/ap-south-1/"
    key = f"{root_prefix}{day}/123456789012_CloudTrail_ap-south-1_example.json.gz"
    event = {
        "eventVersion": "1.08",
        "eventTime": now.isoformat(),
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "ap-south-1",
        "eventID": "live-shape-example-123",
        "userIdentity": {"type": "IAMUser", "userName": "operator"},
        "sourceIPAddress": "203.0.113.15",
    }
    body = gzip.compress(json.dumps({"Records": [event]}).encode("utf-8"))
    fake_s3 = _FakeS3([{"Key": key, "LastModified": now}], {key: body})
    monkeypatch.setattr(aws_connectors, "_session", lambda region, profile=None: _FakeSession(fake_s3))

    events, metadata = aws_connectors.sync_cloudtrail_s3_logs(
        bucket="cloudtrail-example", prefix=root_prefix, region="ap-south-1", hours=1, max_objects=5
    )

    assert len(events) == 1
    assert events[0].event_name == "CreateAccessKey"
    assert events[0].ingestion_source == "aws_s3_cloudtrail"
    assert events[0].source_ref == f"s3://cloudtrail-example/{key}"
    assert metadata["processed_objects"] == 1
    assert metadata["skipped_objects"] == 0
