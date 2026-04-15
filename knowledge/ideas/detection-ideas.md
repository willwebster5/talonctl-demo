<!-- TIER: L3 | LOADED BY: on-demand during detection engineering sessions -->
<!-- UPDATE: When triage or hunting reveals detection gaps -->

# Detection Ideas

## AWS — Unusual Cross-Account AssumeRole
- **Hypothesis:** An attacker with credentials in one account assumes roles in other accounts
- **Data source:** CloudTrail
- **Key fields:** `eventName=AssumeRole`, `resources.ARN` (target), `userIdentity.arn` (source)
- **Challenge:** Need to baseline normal cross-account patterns for CI/CD
- **MITRE:** TA0008:T1550.001 (Lateral Movement / Use Alternate Authentication Material)

## EntraID — Conditional Access Policy Modification
- **Hypothesis:** An attacker with Global Admin disables MFA or device compliance requirements
- **Data source:** EntraID Audit Logs
- **Key fields:** `activityDisplayName=Update conditional access policy`, `targetResources`
- **Challenge:** Legitimate policy updates happen during security team changes
- **MITRE:** TA0005:T1562.001 (Defense Evasion / Impair Defenses: Disable or Modify Tools)

## GitHub — Repository Visibility Change to Public
- **Hypothesis:** Sensitive internal repo accidentally or maliciously made public
- **Data source:** GitHub Audit Logs
- **Key fields:** `action=repo.access`, `visibility=public`
- **Challenge:** Some repos are intentionally public (open source projects)
- **MITRE:** TA0010:T1567 (Exfiltration / Exfiltration Over Web Service)
