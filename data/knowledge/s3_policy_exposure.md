# S3 bucket policy and public exposure triage

Category: storage

## Investigating bucket policy changes

Events such as PutBucketPolicy and DeleteBucketPolicy may alter who can access an S3 bucket. A policy change alone does not establish that data was exposed. Inspect the policy document, principal, action, resource, conditions, account, region, and change approval.

Look for broad principals, overly permissive actions, unexpected cross-account access, missing conditions, and related bucket-level configuration changes. Verify exposure using approved configuration and access-analysis tools; do not infer actual data access from a policy change alone.

Recommended defensive checks: review the effective bucket policy and public access block settings; examine relevant S3 data events if they were enabled; check access logs or other available telemetry; identify potential data sensitivity; preserve findings; and remediate only through an authorized change process.

Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html
