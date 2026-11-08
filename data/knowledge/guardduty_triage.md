# Amazon GuardDuty finding triage

Category: detection

## Review a GuardDuty finding

Use the finding type, severity, description, resource details, affected account, region, timestamps, and service-specific action/network details to understand what GuardDuty observed. Severity helps prioritize triage but is not itself a calibrated probability that an account is compromised.

Validate findings against independent sources where available, including CloudTrail API events, identity activity, endpoint or network records, change records, and known maintenance. A finding without supporting context should remain an open hypothesis until the missing evidence is checked.

Recommended defensive checks: record the finding ID and type; identify the affected principal and resource; correlate nearby events; inspect relevant request parameters and response codes; determine business impact; document evidence and uncertainty; and follow the approved incident response procedure.

Reference: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html
Reference: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-severity.html
