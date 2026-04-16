# Monthly SOC Review Playbook

**Trigger:** First Monday of the month, `/soc review monthly`
**Duration:** ~1 hour
**Frequency:** Monthly

---

## Step 1: Generate Monthly Dataset

Run health check with 30-day window:
```bash
python scripts/detection_health.py --period 30 --format json --output /tmp/monthly_health.json
python scripts/detection_health.py --period 30 --format text
```

## Step 2: Coverage Gap Analysis

Review detection counts by platform vs MITRE ATT&CK coverage:
- Use template discovery to enumerate all detections by platform
- Cross-reference MITRE tags in templates against the full ATT&CK matrix
- Identify uncovered techniques per platform

## Step 3: Platform Coverage Balance

Compare detection counts across platforms:
| Platform | Detection Count | Enrichment Functions | Maturity |
|----------|----------------|---------------------|----------|

Flag platforms falling behind their expected maturity level.

## Step 4: Enrichment Function Utilization

For each saved search, count how many detections reference it:
```bash
# For each saved search, grep detection templates for $function_name()
```

Identify:
- Heavily used functions (potential single points of failure)
- Unused functions (cleanup candidates)

## Step 5: Zero-Hit Triage (30-day window)

For each zero-hit detection over 30 days:
- Is the threat scenario unlikely in our environment? (Expected — mark as "rare-event")
- Is the data source active? (Check if the log source has recent events)
- Is the query broken? (Run validate-query)

## Step 6: FP Trends

Compare this month's FP rates against last month's. Measure tuning effectiveness.

## Step 6b: MTTA (Mean Time to Acknowledge)

Query for time between alert creation and first status change (new → in_progress or new → closed).
Note: CrowdStrike Alerts API may not expose creation-to-first-action timestamps directly. Approximate by comparing alert `created_timestamp` against `updated_timestamp` for first status change. Report as average and P95.

## Step 6c: New Memory Patterns This Month

Count entries added to `knowledge/patterns/*.md` this month by checking git history:
```bash
git log --since="1 month ago" --name-only --pretty=format: -- knowledge/patterns/ | sort -u
```

## Step 7: Memory Hygiene

1. Read `knowledge/INDEX.md`
2. For each FP pattern line, check: has this alert type fired in the last 90 days?
   - Query: `get_alerts(pattern_name="<detection_name>", time_range="90d", max_results=1)`
   - If no hits: mark as `[stale]` in the platform detail file
3. For patterns already marked `[stale]`: verify if the infrastructure still exists
   - Account still active? User still employed? Service still running?
   - If no: change to `[retired]` and remove from MEMORY.md index
4. Report: "X patterns active, Y stale, Z retired this month"

## Step 8: Output

Save monthly report to `docs/reports/monthly/YYYY-MM.md`:
- Coverage gap highlights
- Platform balance assessment
- Zero-hit triage decisions
- FP trend analysis
- Tuning backlog updates
- Next month's priorities
