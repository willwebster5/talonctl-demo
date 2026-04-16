# Playbook: GitHub Audit Log

**Triggers on:**
- `ngsiem:` composite ID prefix + detection name containing "GitHub"
- Source filter: `source_type=github` (NOT `#Vendor` or `#repo` — GitHub uses a different filter pattern)

**Source:** GitHub webhook audit events forwarded into CrowdStrike NGSIEM
**Tunable in NGSIEM:** Yes — detection templates in `resources/detections/github/`

## What These Alerts Mean

GitHub audit log events capture repository operations, branch management, permission changes, and code push activity. The 5 current detections cover:

| Detection | File | What It Detects |
|-----------|------|----------------|
| Direct Push to Protected Branch | `github___direct_push_to_protected_branch.yaml` | Human user pushing directly to main/staging/master bypassing merge queue |
| Force Push Detected | `github___force_push_detected.yaml` | Force push to any branch (history rewrite) |
| Force Push to Protected Branch | `github___force_push_to_protected_branch.yaml` | Force push specifically targeting protected branches |
| Multiple Branch Deletions | `github___multiple_branch_deletions.yaml` | 5+ branch deletions in a short window |
| Protected Branch Deleted | `github___protected_branch_deleted.yaml` | Deletion of a protected branch |

## Key Fields

| Field | Description |
|-------|-------------|
| `Vendor.sender.login` | GitHub username performing the action |
| `Vendor.sender.type` | `"User"` or `"Bot"` (note: machine accounts show as `"User"`) |
| `Vendor.sender.email` | Sender email (often noreply for bots) |
| `event.action` | GitHub webhook event action |
| `Vendor.repository.full_name` | `org/repo` format |
| `Vendor.ref` | Branch reference (e.g., `refs/heads/main`) |
| `Vendor.forced` | `"true"` if force push |
| `Vendor.created` | `"true"` if branch created |
| `Vendor.deleted` | `"true"` if branch deleted |
| `Vendor.head_commit.message` | Head commit message |
| `Vendor.head_commit.id` | Head commit SHA |
| `Vendor.compare` | GitHub compare URL for the push |
| `github.sender_category` | Enriched field from `$github_classify_sender_type()`: `"human"`, `"bot"`, `"app"` |
| `github.actor` | Enriched actor field from `$github_enrich_event_context()` |
| `github.repository` | Enriched repo name |
| `github.organization` | Enriched org name |
| `github.branch` | Extracted branch name (from `Vendor.ref`) |
| `github.operation_type` | `"NormalPush"`, `"ForcePush"`, `"BranchCreate"`, `"BranchDelete"` |

## Base Query Filter

```cql
source_type=github
```

**IMPORTANT:** GitHub events do NOT use `#Vendor="github"` or `#repo=` patterns. This is a known gotcha.

## Investigation Queries

### 1. Actor's GitHub Activity (24h)

All events by a specific GitHub user.

```cql
source_type=github
| Vendor.sender.login="{{github_username}}"
| $github_enrich_event_context()
| $github_classify_sender_type()
| table([@timestamp, github.actor, github.sender_category, event.action, github.repository, github.branch, github.operation_type, Vendor.head_commit.message], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h

### 2. Repository-Specific Activity (7d)

All events on the affected repo.

```cql
source_type=github
| Vendor.repository.full_name="{{org/repo}}"
| $github_enrich_event_context()
| $github_classify_sender_type()
| table([@timestamp, github.actor, github.sender_category, event.action, github.branch, github.operation_type, Vendor.head_commit.message], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 3. Branch Operations — Deletions and Force Pushes (7d)

High-risk branch operations across all repos.

```cql
source_type=github
| Vendor.deleted="true" OR Vendor.forced="true"
| $github_enrich_event_context()
| $github_classify_sender_type()
| table([@timestamp, github.actor, github.sender_category, github.repository, github.branch, github.operation_type], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 4. Permission and Settings Changes (7d)

Team membership, collaborator additions, repository visibility.

```cql
source_type=github
| event.action=/(member|team|collaborator|repository.visibility|branch_protection)/
| $github_enrich_event_context()
| table([@timestamp, Vendor.sender.login, event.action, Vendor.repository.full_name], limit=50, sortby=@timestamp, order=desc)
```
**Time range:** 7d

### 5. Cross-Source Correlation (24h)

Same user (by email mapping) across EntraID, AWS, SASE/VPN. Note: GitHub username != email — manual mapping required.

```cql
"{{user_email}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, #event.dataset, event.action, source.ip, #event.outcome], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h centered on alert timestamp

## Available Enrichment Functions

GitHub has 4 enrichment functions (better coverage than most platforms):
- `$github_enrich_event_context()` — add repository, org, actor metadata
- `$github_classify_sender_type()` — human vs bot vs app classification
- `$github_apply_exclusions()` — known-good pattern filtering
- `$github_flag_risky_operations()` — risk scoring for sensitive operations

## Triage Checklist

1. **Find the detection template:** Search `resources/detections/github/` for the alert name. Read the CQL to understand the trigger.
2. **Who is the actor?** Check `github.sender_category` — `"bot"` = machine account (likely automation). `"human"` = developer, needs review.
3. **What branch was affected?** `main`/`master` = production risk. `staging` = pre-production. Feature branches = lower risk.
4. **Was this a PR merge?** Check `Vendor.head_commit.message` for `Merge pull request #N` or squash merge patterns. PR merges are expected.
5. **Was this a force push?** `Vendor.forced="true"` = history rewrite. More dangerous than normal push.
6. **Branch deletions — post-merge cleanup?** Check if deleted branches are Jira-ticketed feature branches (`<PROJECT_KEY>-*` patterns). 5-12+ at once is normal cleanup.
7. **Check the commits:** Use the `Vendor.compare` URL to review actual code changes.

## Common FP Patterns

| FP Pattern | How to Identify | Resolution |
|---|---|---|
| Branch cleanup after merge | 5-12+ Jira-ticketed branches deleted at once (`<PROJECT_KEY>-*` patterns), no protected branches | Normal post-merge cleanup |
| Bot machine account pushes | `github.sender_category="bot"`, numeric noreply email, lockfile/dependency updates | Filtered by `$github_classify_sender_type()` + `github.sender_category != "bot"` |
| PR merge to protected branch | `Vendor.head_commit.message` matches `Merge pull request #N` or `Merge branch` pattern | Excluded by `_IsReleaseMerge` filter in detection |
| Squash merge with PR reference | `Vendor.head_commit.message` contains `(#123)` PR number pattern | Excluded by `_IsReleaseMerge` filter |

## Classification Guidance

| Signal | Likely FP | Likely TP |
|--------|-----------|-----------|
| Actor | Bot/machine account, known developer | Unknown user, former employee |
| Branch | Feature branch, Jira-ticketed | main/master/staging |
| Operation | Normal push, PR merge, branch cleanup | Force push, direct push bypassing review |
| Content | Lockfile updates, dependency bumps | Source code changes, CI/CD config, secrets |
| Time | Business hours | Off-hours, weekend |
| Scope | Single repo, single branch | Multiple repos, protected branches |

## Closing the Alert

**FP:**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="FP — <reason>",
  tags=["false_positive", "github"]
)
```
Then proceed to Phase 3B if tuning is needed — edit the detection template in `resources/detections/github/`.

**TP:**
Escalate via Phase 3C workflow.
```
mcp__crowdstrike__update_alert_status(
  status="in_progress",
  comment="TP confirmed: <summary>",
  tags=["true_positive"]
)
```

## Platform-Specific Caveats

- **`source_type=github`, NOT `#Vendor` or `#repo`.** This is a unique filter pattern — all other platforms use `#Vendor` or `#repo`.
- **Machine accounts show as `Vendor.sender.type="User"`.** GitHub machine accounts registered as Users (not GitHub Apps) pass the `"User"` type filter. Use `github.sender_category` from `$github_classify_sender_type()` instead.
- **GitHub username != email.** `Vendor.sender.login` (e.g., `jdoe-gh`) does not match email (`jdoe@example.com`). No automated lookup exists yet. Cross-source correlation requires manual username-to-email mapping.
- **`Vendor.ref` includes full path.** Branch name must be extracted from `refs/heads/<branch>` using regex.
