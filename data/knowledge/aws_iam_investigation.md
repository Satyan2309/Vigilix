# AWS IAM investigation guidance

Category: identity

## Investigating IAM policy and privilege changes

Review identity and access management changes in context. Relevant CloudTrail API names can include AttachUserPolicy, PutUserPolicy, AttachRolePolicy, PutRolePolicy, CreatePolicyVersion, SetDefaultPolicyVersion, UpdateAssumeRolePolicy, and AddUserToGroup. The presence of one event is not proof of malicious activity: compare the actor, target identity, policy ARN or policy document, source IP, user agent, change ticket, and normal administrative patterns.

For a suspected privilege escalation, establish which principal initiated the change and which permissions changed. Check whether the actor was expected to make the change, whether the target policy grants broad administrative access, and whether the activity is followed by new credentials, unexpected API calls, or audit-logging changes.

Recommended defensive checks: verify the change with the account owner; inspect policy versions and attached policies; review nearby CloudTrail events for the same principal and source; check MFA and session context where available; preserve event IDs; and follow the organization's approved rollback process if the change is unauthorized.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html
