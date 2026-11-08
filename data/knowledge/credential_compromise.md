# Suspected cloud credential compromise

Category: identity

## Triage sequence

A sequence involving repeated failed sign-ins, a later successful sign-in, creation of new credentials, privilege expansion, or unfamiliar API use can warrant investigation. These events can also result from legitimate user activity or automation. Treat them as evidence to validate, not as automatic proof of compromise.

Establish the principal and source context. Compare source IP, user agent, region, session information, MFA signals if available, event time, and the user's expected duties. Check whether the same principal created an access key and then used it for operations it did not normally perform. Review access-key metadata and activity without exposing secret key material.

Recommended defensive checks: contact the identity owner through a trusted channel; review sign-in context and CloudTrail events; inspect access-key last-used information; identify affected resources; preserve relevant events; and follow the incident-response playbook to disable or rotate credentials only after authorization.

Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html
