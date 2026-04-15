<!-- TIER: L2 | LOADED BY: Phase 2 (Triage) when investigating alerts -->
<!-- UPDATE: When you discover useful CQL patterns or field gotchas -->

# Investigation Techniques

## Quick Lookups

### User Activity Timeline
```
#repo!=xdr_*
| userIdentity.arn = "<ARN>" OR userPrincipalName = "<UPN>" OR actor = "<username>"
| select([@timestamp, #Vendor, eventName, sourceIPAddress, userAgent])
| sort(@timestamp, order=asc)
```

### IP Reputation Check
```
#repo!=xdr_*
| source.ip = "<IP>" OR destination.ip = "<IP>"
| groupBy([source.ip, destination.ip, #Vendor], function=[count(), min(@timestamp), max(@timestamp)])
```

### Source IP Activity Spread
```
#repo!=xdr_*
| source.ip = "<IP>"
| groupBy([#Vendor, eventName], function=count())
| sort(_count, order=desc)
```

## Field Gotchas

- **CloudTrail userIdentity:** Can be `type=AssumedRole` (role session) or `type=IAMUser` — check `arn` for the actual identity
- **EntraID dual schema:** Sign-in logs use `userPrincipalName`, audit logs use `initiatedBy.user.userPrincipalName` — different fields for the same concept
- **GitHub actor:** Bot accounts end with `[bot]` (e.g., `dependabot[bot]`), service accounts don't
- **VPC Flow Logs:** `action=ACCEPT` means the security group/NACL allowed the traffic, not that a connection was established
