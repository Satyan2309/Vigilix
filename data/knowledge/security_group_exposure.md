# Security group and network exposure triage

Category: network

## Investigating security group rule changes

AuthorizeSecurityGroupIngress and related APIs can alter network reachability. Assess protocol, port ranges, source CIDRs, target security group, VPC, and whether the change matches the expected deployment. A rule permitting broad sources to an administrative port may deserve prompt review, but context matters.

Correlate configuration changes with deployment records and subsequent network or endpoint alerts. Cloud audit events demonstrate that a configuration operation occurred; they do not alone prove that a remote connection succeeded or that a workload was compromised.

Recommended defensive checks: inspect the effective security group rules; validate exposed ports and source ranges; use approved network reachability analysis; check relevant flow logs if enabled; and remove unintended exposure through the normal change-control process.

Reference: https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
