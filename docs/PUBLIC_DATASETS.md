# Public CloudTrail dataset attribution and limitations

Vigilix AI can optionally download this dataset after the user clicks **Download and import public dataset** in the console:

- Repository: <https://github.com/ryan91021/cloudtrail-anomaly-detection>
- Dataset file: <https://github.com/ryan91021/cloudtrail-anomaly-detection/blob/main/data/dataset.csv>
- Raw download: <https://raw.githubusercontent.com/ryan91021/cloudtrail-anomaly-detection/main/data/dataset.csv>
- License: MIT (as declared by the source repository; see its `LICENSE` file)

The source repository describes the dataset as 26,550 AWS CloudTrail management events collected from a personal AWS sandbox during 2026-01-07 through 2026-02-25. It reports anonymizing routable source IPs to RFC 5737 documentation ranges and removing account IDs, ARNs, access keys, user names, role names, and instance IDs. The repository also documents a single suspicious sequence on 2026-01-26 involving denied `AssumeRole`, `StopLogging`, and `DeleteTrail` calls within 150 seconds.

## Important limitations

- This is **public anonymized research data**, not telemetry from the user’s AWS account and not live/streaming data.
- The source repository describes one real incident. This is too little ground truth to claim broad detection effectiveness.
- The full dataset is not bundled with Vigilix AI. A user-triggered download stores it under `data/external_datasets/`, which is git-ignored.
- Vigilix AI preserves the source URL and SHA-256 hash in `SOURCE_METADATA.json` so a user can trace the downloaded file.
- Do not redistribute the data independently of the source license and attribution. Re-check the source repository and license before redistribution or public deployment.
- Real cloud audit logs may reveal sensitive operational details. Review all event data and any custom documents before sending context to a hosted LLM.

The importer uses a fixed, reviewed URL rather than accepting arbitrary download URLs. It enforces a 50 MB download cap and identifies imported rows with the provenance tag `public_anonymized_cloudtrail`.
