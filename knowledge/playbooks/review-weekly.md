# Weekly SOC Review Playbook

**Trigger:** `/soc review weekly` or automated Monday morning
**Duration:** ~15 minutes of human review
**Frequency:** Weekly

---

## Step 1: Collect Data

Run the detection health checker for the last 7 days:
```bash
python scripts/detection_health.py --period 7 --format json --output /tmp/weekly_health.json
python scripts/detection_health.py --period 7 --format text
```

If CI has already run this week, read the latest artifact instead.

## Step 2: Alert Volume Review

Query NGSIEM for alert volume by detection (7 days):
```
ngsiem_query:
  query: '#repo=xdr_indicatorsrepo Ngsiem.event.type="ngsiem-rule-trigger-event" | groupBy(rule.name, function=[count(), min(@timestamp), max(@timestamp)]) | sort(_count, order=desc) | head(20)'
  time_range: "7d"
```

**What to look for:**
- Detections generating >50 alerts/day — candidates for tuning
- New detections appearing in top 20 for first time — verify they are working as intended
- Detections that dropped off from last week — may indicate a broken dependency

## Step 3: New Zero-Hit Detections

Compare this week's zero-hit list against last week's. New zero-hit detections (were firing, now silent) are higher priority than persistent zero-hits.

Read the detection metrics CSV:
```bash
# Show detections that had hits last week but zero this week
# (requires two weeks of data)
```

## Step 4: FP Rate Check

Query for alerts closed as false positive in the last 7 days.
Note: Alert disposition (FP/TP) is only available via the Alerts API, not NGSIEM.
```
get_alerts:
  status: "closed_false_positive"
  time_range: "7d"
  max_results: 200
```
Then group the results by name to find top FP generators.

Flag any detection with >70% FP rate for tuning backlog.

## Step 4b: FP Close Count by Detection

From the Step 4 results, group FP-closed alerts by detection rule name:
- Count FP closures per detection rule
- Compare against previous week
- Flag rules with increasing FP trend

## Step 4c: Open Alerts from Prior Sessions

Check for alerts that were triaged but not closed:
```
get_alerts:
  status: "in_progress"
  time_range: "30d"
  max_results: 50
```
These represent investigation continuity gaps — alerts that fell between sessions.

## Step 5: Error Check

Run dependency validation:
```bash
python scripts/resource_deploy.py plan --skip-query-validation 2>&1 | grep -A2 "Broken.*Dependencies"
```

## Step 6: Output

Post a summary to a GitHub issue labeled `soc-review-weekly` with:
- Alert volume trends (vs last week)
- New zero-hit detections
- Top FP generators
- Any broken dependencies
- Action items
