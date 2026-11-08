# CloudTrail logging integrity investigation

Category: audit-logging

## Audit logging changes

CloudTrail events such as StopLogging, DeleteTrail, UpdateTrail, and PutEventSelectors can change audit collection or coverage. These operations can be legitimate maintenance, so verify the actor, account, region, trail, event selectors, and approved maintenance window.

A logging change occurring shortly after a privilege-related operation is more concerning than an isolated change. Correlate events by principal and timestamp, then look for gaps in expected logging, additional policy changes, suspicious credential activity, or unusual API calls before and after the change.

Recommended defensive checks: confirm trail status and multi-region coverage; validate delivery to the expected S3 bucket and/or CloudWatch Logs destination; verify log-file validation settings where configured; review the surrounding event history; and restore expected logging using an authorized administrator if the change is not approved.

CloudSentry should never execute a logging restoration automatically. It should provide the relevant evidence and require an authorized analyst to decide.

Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-best-practices.html
Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html
