# Vigilix AI detection rule interpretation

Category: detection-rules

## Current MVP rule intent

Vigilix AI's initial deterministic rules flag high-impact AWS operations, including IAM policy changes, new access-key creation, security-group ingress changes, bucket-policy changes, and CloudTrail logging changes. A rule match means the event deserves contextual review, not that it is conclusively malicious.

Correlation rules raise the investigation priority when a single known principal performs credential creation followed by privilege change within sixty minutes; privilege change followed by audit-logging change within sixty minutes; or failed ConsoleLogin events followed by a successful ConsoleLogin within ten minutes. Current MVP correlation uses shared principal identity and parsed timestamps. It does not establish source attribution when fields are missing, and unknown values should not be treated as a match except where the login rule explicitly notes a missing IP.

Findings should include the raw event ID, normalized fields, rule ID, time window, and the exact event IDs participating in a correlation. Severity is a heuristic triage priority and is not a calibrated probability of compromise.
