# Playbook: Cross-Platform Investigation

**When to use:**
- Any alert where the actor operates across multiple platforms
- Compromised credential investigations (credential used in EntraID, then AWS, then GitHub)
- IP-based correlation (same source IP across multiple services)
- Temporal analysis (activity burst across platforms within a short window)

**Source:** Multiple — correlates events across all NGSIEM log sources
**Tunable in NGSIEM:** N/A — this is a supplementary investigation playbook, not alert triage

## When to Invoke This Playbook

This playbook is a **reference for investigation techniques**, not an alert-specific triage guide. Invoke it as a supplement during Phase 2 (investigation) of any platform-specific triage when:
- The alert involves a user who operates across multiple platforms
- Initial triage raises questions about activity on other platforms
- You need to scope a compromise beyond the triggering alert's platform

## Identity Correlation

The same person has different identifiers across platforms. Email/UPN is the common key for most platforms.

| Platform | Identity Field | Format | Example |
|----------|---------------|--------|---------|
| EntraID | `user.email` / `user.full_name` | UPN | `jdoe@example.com` |
| AWS | `Vendor.userIdentity.arn` | ARN (email embedded in session name) | `arn:aws:sts::123:assumed-role/AWSReservedSSO_.../jdoe@example.com` |
| Google | `actor.email` | Email | `jdoe@example.com` |
| GitHub | `Vendor.sender.login` | GitHub username (NOT email) | `jdoe-gh` |
| SASE / VPN | `user.name` / `Vendor.vpn_user_email` | Email | `jdoe@example.com` |
| CrowdStrike EDR | `UserName` | `DOMAIN\user` or `user` (local) | `<DOMAIN>\jdoe` |
| Phish reporting platform | `phisher.Email.reported_by` | Email | `jdoe@example.com` |

**Mapping notes:**
- Email is the common key for EntraID, AWS (extract from ARN session name), Google, SASE/VPN, phish reporting platform
- **GitHub requires separate mapping** — `Vendor.sender.login` is a GitHub username, not an email. No automated lookup file exists yet. Use `Vendor.sender.email` if populated (often a noreply address for bots).
- **CrowdStrike EDR** uses Windows domain accounts — strip the domain prefix and match on username
- The `$identity_enrich_from_email()` saved search exists for cross-platform identity resolution

## Investigation Queries

### 1. User Activity Across All Sources (24h)

The broadest possible query — every event mentioning this user across all platforms.

```cql
"{{user_email}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, #event.dataset, event.action, source.ip, #event.outcome], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h centered on alert timestamp

### 2. IP Activity Across All Sources (24h)

Every event from a specific source IP, regardless of platform.

```cql
source.ip="{{ip}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, user.name, user.email, event.action, #event.outcome], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 3. Temporal Clustering Analysis (1h window)

Group activity by platform and time bucket to visualize cross-platform bursts.

```cql
"{{user_email}}"
| #repo!="xdr*"
| bucket(span=5m)
| groupBy([_bucket, #Vendor], function=count())
| sort(_bucket)
```
**Time range:** 1h centered on alert timestamp

### 4. Geo Anomaly — Same User, Different Locations

Check if a user appears from geographically impossible locations across platforms within a short window.

```cql
"{{user_email}}"
| #repo!="xdr*"
| source.ip=*
| ipLocation(source.ip)
| groupBy([#Vendor, source.ip], function=[
    count(as=events),
    min(@timestamp, as=first_seen),
    max(@timestamp, as=last_seen),
    selectLast([source.ip.country, source.ip.city, source.ip.org])
  ])
| sort(first_seen)
```
**Time range:** 24h

### 5. Enrichment-Assisted Cross-Platform Query

Use available enrichment functions for richer context.

```cql
"{{user_email}}"
| #repo!="xdr*"
| $identity_enrich_from_email()
| $score_geo_risk()
| $trusted_network_detector()
| table([@timestamp, #Vendor, event.action, source.ip, _geo_risk_score, _is_trusted_network, _identity_type], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h

## Cross-Platform Attack Chains

Common multi-platform attack sequences to look for during investigation:

| Attack Pattern | Platforms | What to Look For |
|---|---|---|
| Credential compromise then cloud pivot | EntraID + AWS/GCP | Risky sign-in → SSO into cloud console → privilege escalation |
| Phishing then endpoint then lateral | Phish reporting platform + CrowdStrike EDR + EntraID | Reported phish → DNS hit on endpoint → new sign-in from that endpoint |
| VPN abuse then internal access | SASE/VPN + EntraID + AWS | Unusual VPN session → sign-ins from VPN IP → cloud API calls |
| Code repo compromise then supply chain | GitHub + AWS + CrowdStrike EDR | Force push / workflow edit → CI/CD pipeline change → deployment |
| Account takeover chain | EntraID + Google + GitHub | Password reset → MFA change → SSO into downstream apps |

## Available Cross-Platform Enrichment Functions

- `$identity_enrich_from_email()` — resolve identity across platforms
- `$score_geo_risk()` — geographic risk scoring
- `$trusted_network_detector()` — known corporate/VPN network identification
- `$create_baseline_7d()` / `$create_baseline_60d()` / `$create_baseline_90d()` — behavioral baselines

## Platform Source Filters Reference

Quick reference for scoping to a specific platform when following an attack chain:

| Platform | Source Filter |
|----------|--------------|
| AWS CloudTrail | `(#repo="cloudtrail" OR #repo="fcs_csp_events") #Vendor="aws" #repo!="xdr*"` |
| EntraID / Microsoft | `#Vendor="microsoft" #event.dataset=/entraid/ #repo!="xdr*"` |
| Google Cloud (GCP) | `#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"` |
| Google Workspace | `#repo="3pi_google_workspace_logs" #Vendor="google" #repo!="xdr*"` |
| SASE / VPN | `#Vendor="<sase_vendor>" #repo!="xdr*"` |
| GitHub | `source_type=github` |
| CrowdStrike EDR | `#event_simpleName=<EventType>` (native telemetry) |
| Phish reporting platform | `#Vendor="<phish_vendor>"` |
