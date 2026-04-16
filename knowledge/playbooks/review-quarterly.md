# Quarterly SOC Review Playbook

**Trigger:** First week of quarter, `/soc review quarterly`
**Duration:** ~half day
**Frequency:** Quarterly

---

## Step 1: Generate Quarterly Dataset

Run health check with 90-day window:
```bash
python scripts/detection_health.py --period 90 --format json --output /tmp/quarterly_health.json
python scripts/detection_health.py --period 90 --format text
```

## Step 2: Stale Detection Cleanup

Detections with zero hits for 90+ days are candidates for removal:
- Review each against its intended threat scenario
- Confirm with user before disabling or removing
- Document decision in quarterly report

## Step 3: MITRE ATT&CK Coverage Scoring

Produce formal coverage percentages:
- By tactic (Initial Access, Execution, Persistence, etc.)
- By technique within each tactic
- Compare against previous quarter

## Step 4: Detection Quality Scoring

For each detection, compute scores (0.0-1.0):
- **hit_rate_score**: Expected vs actual fire rate
- **fp_rate_score**: 1.0 - fp_rate
- **severity_accuracy_score**: Requires human input
- **enrichment_score**: Uses all available platform functions?
- **overall_quality_score**: Weighted average

Update `detection_quality_scores.csv` and deploy.

## Step 5: Platform Maturity Assessment

Rate each platform's detection program:
| Platform | Detections | Enrichments | Hit Rate | FP Rate | Maturity |
|----------|-----------|-------------|----------|---------|----------|

Set targets for next quarter.

## Step 5b: Memory Health

Count pattern lifecycle status across all `knowledge/patterns/*.md` files:
```bash
grep -c "\[active\]" knowledge/patterns/*.md
grep -c "\[stale\]" knowledge/patterns/*.md
grep -c "\[retired\]" knowledge/patterns/*.md
```

Compare against previous quarter. Healthy trend: active count grows slowly, stale patterns get resolved (retired or reactivated), retired count shows cleanup is happening.

## Step 6: Housekeeping

- Saved search consolidation (duplicate/near-duplicate functions)
- State file hygiene (run sync, verify consistency)
- RTR script audit (still needed? still functional?)
- Lookup file freshness (Tor exit nodes, known-good lists)

## Step 7: Output

Save quarterly report to `docs/reports/quarterly/YYYY-QN.md`:
- Executive summary with KPI trends
- Detection quality scores
- Platform maturity ratings
- Cleanup actions taken
- Next quarter goals

Update `detection_quality_scores.csv` and deploy via:
```bash
python scripts/resource_deploy.py apply --resources=lookup_file --names=detection_quality_scores --auto-approve
```
