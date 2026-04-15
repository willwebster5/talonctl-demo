<!-- TIER: L1 | LOADED BY: every session | PURPOSE: Ground all analysis in Pinnacle's environment -->
<!-- UPDATE: When infrastructure changes (new services, team changes, data source additions) -->

# Pinnacle Technology — Environmental Context

## Company Profile

- **Industry:** B2B SaaS (developer productivity tools)
- **Headcount:** ~200 total, ~50 engineers with production access
- **Security team:** 5 (1 manager, 2 detection engineers, 2 SOC analysts)
- **Compliance:** SOC 2 Type II

## Cloud Infrastructure

### AWS (Primary Cloud)
- **Accounts:** `pinnacle-prod` (112233445566), `pinnacle-staging` (223344556677), `pinnacle-dev` (334455667788)
- **Primary region:** us-east-1 (some workloads in us-west-2)
- **Key services:** EC2, ECS (containerized apps), S3, RDS (PostgreSQL), Lambda, CloudFront
- **Logging:** CloudTrail (all accounts, all regions), VPC Flow Logs (prod only), S3 access logs
- **CI/CD service accounts:** `github-actions-deploy`, `terraform-automation`
- **Known noise:** `terraform-automation` makes frequent IAM and Security Group changes during business hours

### Identity — EntraID
- **Tenant:** pinnacletech.onmicrosoft.com
- **SSO apps:** AWS SSO, GitHub, Google Workspace, Slack, Jira, Datadog
- **Conditional Access:** MFA required for all users, block legacy auth, compliant device required for prod AWS
- **Break-glass accounts:** `emergency-admin@pinnacletech.com` (alerts on any use)
- **Service accounts:** `svc-sso-sync`, `svc-scim-provisioning`
- **Known noise:** `svc-scim-provisioning` generates high-volume directory sync events

### Source Control — GitHub
- **Org:** `pinnacle-tech`
- **Key repos:** `pinnacle-api` (main product), `pinnacle-infra` (Terraform), `pinnacle-data` (data pipelines)
- **Branch protection:** Required reviews on main for all repos
- **Actions:** Self-hosted runners in `pinnacle-prod` AWS account
- **Known noise:** Dependabot creates many PRs in `pinnacle-api` (automated, expected)

### Collaboration — Google Workspace
- **Domain:** pinnacletech.com
- **Key groups:** `engineering@`, `security@`, `oncall@`
- **DLP:** Basic rules for PII in email/Drive
- **Known noise:** Marketing team uses third-party email tools that trigger suspicious login patterns

## CrowdStrike Deployment

- **Falcon sensor:** All endpoints (macOS and Linux), latest sensor version
- **NGSIEM:** Log aggregation from CloudTrail, EntraID, GitHub, Google Workspace, VPC Flow Logs, Falcon telemetry
- **Fusion:** Automated workflows for alert enrichment and notification

## Data Sources in NGSIEM

| Source | Repository | Volume | Key Fields |
|--------|-----------|--------|------------|
| CloudTrail | search-all | ~5M events/day | eventName, userIdentity, sourceIPAddress, requestParameters |
| EntraID Sign-in Logs | search-all | ~50K events/day | userPrincipalName, appDisplayName, status, ipAddress, riskState |
| EntraID Audit Logs | search-all | ~10K events/day | activityDisplayName, targetResources, initiatedBy |
| GitHub Audit Logs | search-all | ~20K events/day | action, actor, org, repo |
| Google Workspace | search-all | ~30K events/day | event_name, actor.email, target |
| VPC Flow Logs | search-all | ~100M events/day | srcaddr, dstaddr, dstport, action, protocol |
| Falcon Endpoint | xdr_* | varies | event_simpleName, aid, UserName, CommandLine |

## Known Legitimate Patterns

These patterns are expected and should not trigger alerts without additional context:

1. **CI/CD IAM changes:** `github-actions-deploy` and `terraform-automation` make IAM/SG changes during US business hours
2. **SCIM sync floods:** `svc-scim-provisioning` generates bursts of directory events on employee onboarding days
3. **Dependabot PRs:** Automated dependency update PRs in `pinnacle-api` — high volume, expected
4. **Marketing logins:** Marketing team members log in from various IPs due to travel and third-party tools
5. **Break-glass testing:** Quarterly test of `emergency-admin` account (documented, announced)

## Escalation Contacts

| Role | Contact | When |
|------|---------|------|
| SOC Lead | Alex Chen | First escalation for TP alerts |
| Detection Engineering | Jordan Park | Detection tuning, new rule requests |
| Security Manager | Sam Rivera | P1 incidents, compliance questions |
| DevOps On-call | oncall@pinnacletech.com | Infrastructure questions, containment approval |
