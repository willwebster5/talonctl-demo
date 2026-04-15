<!-- TIER: L2 | LOADED BY: Phase 3 (Classification) for EntraID alerts -->
<!-- UPDATE: After every EntraID alert triage — add FP/TP patterns -->

# EntraID — FP/TP Patterns

## False Positive Patterns

### SCIM Provisioning Sync
- **Detection:** (applies to future EntraID detections)
- **Pattern:** `svc-scim-provisioning` generates directory sync bursts on onboarding days
- **Identifying fields:** `initiatedBy.app.displayName` = "SCIM Connector"
- **Action:** Exclude SCIM service principal from directory change detections

### Marketing Team Travel Logins
- **Detection:** (applies to future sign-in anomaly detections)
- **Pattern:** Marketing team logs in from various IPs due to travel and third-party email tools
- **Identifying fields:** `userPrincipalName` in marketing team, `appDisplayName` = third-party tool
- **Action:** Use group-based risk scoring rather than hard IP blocks

## True Positive Indicators

(No TP patterns recorded yet)
