<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for AWS alerts -->
<!-- UPDATE: After every AWS alert triage — add FP/TP patterns -->

# AWS — FP/TP Patterns

## False Positive Patterns

<!-- Format:
### [Short description]
- **Detection:** resource_id
- **Pattern:** What makes this a FP
- **Identifying fields:** Key fields to check
- **Action:** How to tune (exclusion, threshold, etc.)
-->

### CI/CD IAM Changes
- **Detection:** (applies to future IAM detections)
- **Pattern:** `github-actions-deploy` and `terraform-automation` make IAM/SG changes during business hours
- **Identifying fields:** `userIdentity.arn` contains service account name
- **Action:** Exclude CI/CD service accounts by ARN

## True Positive Indicators

<!-- Format:
### [Short description]
- **Detection:** resource_id
- **Pattern:** What makes this a TP
- **Key evidence:** Fields/values that confirm
-->

(No TP patterns recorded yet)
