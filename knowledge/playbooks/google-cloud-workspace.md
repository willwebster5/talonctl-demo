# Playbook: Google Cloud/Workspace

**Triggers on:**
- `ngsiem:` composite ID prefix + detection name containing "Google", "GCP", or "Workspace"
- No `fcs:` or `thirdparty:` prefix expected — all Google detections are custom NGSIEM rules

**Source:**
- GCP Cloud Audit: `#repo="3pi_google_cloud_audit_logs" #Vendor="google"`
- Google Workspace: `#repo="3pi_google_workspace_logs" #Vendor="google"`

**Tunable in NGSIEM:** Yes — detection templates in `resources/detections/google/`

## What These Alerts Mean

### GCP Cloud Audit
Google Cloud Platform audit logs capture administrative activity across GCP services: IAM policy changes, Compute Engine operations, Storage bucket modifications, KMS key management, App Engine deployments, BigQuery access. Detections in `resources/detections/google/` with names starting `Google - Cloud Audit -` monitor these logs.

### Google Workspace
Google Workspace admin audit logs capture user and admin activity: admin console changes, Drive sharing, login events, group management, SAML/SSO grants, calendar operations. Detections with names starting `Google - Workspace -` monitor these logs.

**Two data sources, one playbook.** GCP and Workspace events come from different repos but share the `#Vendor="google"` filter. The playbook separates queries by source where field schemas differ.

## Two Data Sources

| Source | NGSIEM Repo | Key Event Types |
|--------|-------------|-----------------|
| GCP Cloud Audit | `#repo="3pi_google_cloud_audit_logs"` | IAM, Compute, Storage, Network, KMS, App Engine, BigQuery |
| Google Workspace | `#repo="3pi_google_workspace_logs"` | Admin, Drive, Login, Groups, Calendar, SAML |

## Key Fields

### Shared Fields (Both Sources)
| Field | Description |
|-------|-------------|
| `actor.email` | Google identity performing the action |
| `event.action` | API method or admin action name |
| `#event.outcome` | Success/failure |
| `source.ip` | Caller IP |
| `#Vendor` | Always `"google"` |

### GCP Cloud Audit Fields
| Field | Description |
|-------|-------------|
| `#event.module` | `"gcp"` |
| `#event.dataset` | `"gcp.audit"` |
| `service.name` | GCP service (e.g., `iam.googleapis.com`, `storage.googleapis.com`, `compute.googleapis.com`) |
| `cloud.project.id` | GCP project |
| `Vendor.protoPayload.serviceName` | Full GCP service name |
| `Vendor.protoPayload.methodName` | Full API method |
| `Vendor.protoPayload.authenticationInfo.principalEmail` | Actor email (alternative path) |
| `Vendor.protoPayload.serviceData.policyDelta.bindingDeltas[]` | IAM policy change details |

### Google Workspace Fields
| Field | Description |
|-------|-------------|
| `#event.module` | `"workspace"` |
| `Vendor.protoPayload.serviceName` | Usually `admin.googleapis.com` |
| `Vendor.protoPayload.metadata.event[0].eventName` | Workspace event name (e.g., `GRANT_ADMIN_PRIVILEGE`, `CHANGE_APPLICATION_SETTING`) |
| `Vendor.protoPayload.metadata.event[0].eventType` | Event category |

## Base Query Filters

```cql
// GCP Cloud Audit
#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
```

```cql
// Google Workspace
#repo="3pi_google_workspace_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
```

```cql
// Both Google sources (any Google event)
#Vendor="google" #repo!="xdr*"
| #event.kind="event"
```

## Investigation Queries — GCP Cloud Audit

### 1. Actor's GCP Activity Around Alert Time (1h)

Full activity for the actor who triggered the alert.

```cql
#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
| actor.email="{{actor_email}}"
| table([@timestamp, service.name, event.action, #event.outcome, cloud.project.id, source.ip], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 1h centered on alert timestamp

### 2. IAM Changes by Actor (7d)

Track IAM policy modifications — privilege escalation indicator.

```cql
#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| actor.email="{{actor_email}}"
| event.action=/SetIamPolicy|CreateServiceAccountKey|SetOrgPolicy|CreateServiceAccount|CreateRole/
| table([@timestamp, event.action, service.name, cloud.project.id, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 3. Compute and Network Changes (24h)

Firewall rule modifications, instance creation, VPC changes — infrastructure tampering.

```cql
#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| service.name=/compute\.googleapis\.com/
| event.action=/(insert|delete|patch|update)/i
| cloud.project.id="{{project_id}}"
| table([@timestamp, actor.email, event.action, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 4. Service Account Key Creation (7d)

High-risk operation — service account keys enable persistent access outside GCP.

```cql
#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event" #event.outcome="success"
| event.action="google.iam.admin.v1.CreateServiceAccountKey"
| table([@timestamp, actor.email, cloud.project.id, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 5. Cross-Project Activity by Actor (24h)

Same actor across GCP projects — lateral movement equivalent.

```cql
#repo="3pi_google_cloud_audit_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
| actor.email="{{actor_email}}"
| groupBy([cloud.project.id], function=[
    count(as=total_events),
    count(event.action, distinct=true, as=distinct_actions),
    collect([service.name, event.action])
  ], limit=max)
| sort(total_events, order=desc)
```
**Time range:** 24h

## Investigation Queries — Google Workspace

### 6. Admin Activity (7d)

Admin console changes: user creation/deletion, role grants, domain settings.

```cql
#repo="3pi_google_workspace_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
| Vendor.protoPayload.serviceName="admin.googleapis.com"
| actor.email="{{actor_email}}"
| table([@timestamp, actor.email, event.action, "Vendor.protoPayload.metadata.event[0].eventName", #event.outcome, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 7. Drive Sharing Changes (24h)

External sharing, link sharing to "anyone with the link" — data exfiltration risk.

```cql
#repo="3pi_google_workspace_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
| event.action=/change_acl|change_document_visibility|change_user_access/
| actor.email="{{actor_email}}"
| table([@timestamp, actor.email, event.action, #event.outcome, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 8. Login Events (7d)

Suspicious logins, password changes, 2SV disables.

```cql
#repo="3pi_google_workspace_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
| event.action=/login|password|2sv/i
| actor.email="{{actor_email}}"
| table([@timestamp, actor.email, event.action, #event.outcome, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 9. SAML/SSO and Third-Party App Access (7d)

OAuth grants, SAML assertions — post-compromise app access.

```cql
#repo="3pi_google_workspace_logs" #Vendor="google" #repo!="xdr*"
| #event.kind="event"
| event.action=/authorize|token|consent|grant/i
| actor.email="{{actor_email}}"
| table([@timestamp, actor.email, event.action, #event.outcome, source.ip], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 10. Cross-Source Correlation (24h)

Same user across all platforms.

```cql
"{{user_email}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, #event.dataset, event.action, source.ip, #event.outcome], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h centered on alert timestamp

## Triage Checklist

1. **Find the detection template:** Search `resources/detections/google/` for the alert name. Read the CQL filter to understand exactly what triggered.
2. **Which source?** GCP Cloud Audit (`#event.dataset="gcp.audit"`) or Workspace (`#event.module="workspace"`)? This determines the investigation path and available fields.
3. **Who is the actor?** Check `actor.email` — is this a human user, a service account (`@*.gserviceaccount.com`), or a Google-managed service agent (`@*.iam.gserviceaccount.com` with `goog-` prefix)?
4. **Is this automation?** Service accounts with Terraform user agents, CI/CD source IPs, or pipeline-associated emails are likely IaC deployments.
5. **Is this HRIS provisioning?** Workspace admin changes from HRIS sync service account are HR provisioning automation.
6. **Which GCP project?** For GCP alerts, check `cloud.project.id` — sandbox vs production projects have different risk levels.
7. **What was the scope?** Run query 5 to check if the actor operated across multiple GCP projects.
8. **Cross-platform check?** Run query 10 to see if this actor was active on other platforms around the same time.

## Common FP Patterns

| FP Pattern | How to Identify | Resolution |
|---|---|---|
| Terraform/IaC deployments | Service account actor, Terraform UA, CI/CD source IP | Expected automation — verify project and change scope |
| Google-managed service agents | Actor email has `goog-` prefix or ends in `@cloudservices.gserviceaccount.com` | Google internal service activity, not human |
| HRIS provisioning (Workspace) | Admin changes from HRIS sync service account | HR provisioning automation |
| BigQuery scheduled queries | Automated query execution by service accounts | Expected data pipeline activity |
| Admin console browsing | Multiple low-risk admin actions in short window by known admin | Normal admin session, not enumeration |

## Classification Guidance

| Signal | Likely FP | Likely TP |
|--------|-----------|-----------|
| Actor identity | Service account, known admin, HRIS | Unknown human, service account not tied to known automation |
| Action type | Read-only, list, get | Write (SetIamPolicy, delete, insert, CreateServiceAccountKey) |
| Project context | Sandbox, test project | Production, shared services |
| Source IP | Known corporate/VPN range | Unknown IP, VPS provider |
| Scope | Single project, single action | Multi-project activity, IAM changes followed by data access |
| Time | Business hours | Off-hours for the actor's timezone |

## Closing the Alert

**FP:**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="FP — <reason>",
  tags=["false_positive", "google"]
)
```
Then proceed to Phase 3B if tuning is needed — edit the detection template in `resources/detections/google/`.

**TP:**
Escalate via Phase 3C workflow.
```
mcp__crowdstrike__update_alert_status(
  status="in_progress",
  comment="TP confirmed: <summary>",
  tags=["true_positive"]
)
```

## Enrichment Functions (Currently None)

Google has 0 enrichment functions. All investigation context must be extracted manually from raw event fields.

Future candidates:
- `$google_enrich_user_identity()` — extract actor type, domain, project context
- `$google_classify_identity_type()` — human vs service account vs Google-managed agent

## Platform-Specific Caveats

- **Two repos, one vendor:** GCP audit logs use `#repo="3pi_google_cloud_audit_logs"` while Workspace logs use `#repo="3pi_google_workspace_logs"`. Both share `#Vendor="google"` but field schemas differ significantly.
- **Workspace event names are deeply nested:** `Vendor.protoPayload.metadata.event[0].eventName` — not `event.action`. Some detections use the nested field directly.
- **GCP IAM policy changes use `objectArray:eval` or `objectArray:exists`:** Complex array operations on `bindingDeltas[]` — read the detection template CQL to understand the exact trigger condition.
- **No enrichment functions:** Unlike AWS (9 functions) and EntraID (18 functions), Google has zero enrichment functions. All entity classification must be done inline in queries.
