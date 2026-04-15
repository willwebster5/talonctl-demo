<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for GitHub alerts -->
<!-- UPDATE: After every GitHub alert triage — add FP/TP patterns -->

# GitHub — FP/TP Patterns

## False Positive Patterns

### Dependabot Automated PRs
- **Detection:** (applies to future repo change detections)
- **Pattern:** High volume of PRs from `dependabot[bot]` in `pinnacle-api`
- **Identifying fields:** `actor` = "dependabot[bot]", `action` = "pull_request.created"
- **Action:** Exclude bot actors from PR volume anomaly detections

## True Positive Indicators

(No TP patterns recorded yet)
