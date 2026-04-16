# Playbook: CrowdStrike Endpoint (EDR + NGSIEM)

**Triggers on:**
- `ind:` composite ID prefix — EDR behavioral IoA detections (process trees, behaviors)
- `ngsiem:` prefix + detection name containing "CrowdStrike" or "Endpoint"
- `ind:` with `type=signal` and `API Product=automated-lead-context` — Charlotte AI signals (fast-track)
- `cwpp:` prefix — Cloud Workload Protection (container image scans — typically noise)

**Source:**
- EDR IoA: CrowdStrike Falcon sensor behavioral detections (base_sensor repo)
- NGSIEM Custom: Detection templates in `resources/detections/crowdstrike/`
- Charlotte AI: Automated investigation context signals

**Tunable in NGSIEM:**
- EDR IoA (`ind:` prefix): **No** — managed by CrowdStrike ML/behavioral engine
- NGSIEM Custom (`ngsiem:` prefix): **Yes** — detection templates in `resources/detections/crowdstrike/`
- Charlotte AI signals: **No** — fast-track close, not real detections
- CWPP (`cwpp:` prefix): **No** — suppress in Falcon Console if volume warrants

## What These Alerts Mean

### EDR Behavioral IoA (`ind:` prefix)
The Falcon sensor detected a behavioral indicator of attack on an endpoint. These are ML-driven or signature-based detections that fire on process execution, file writes, network connections, or registry changes that match known attack patterns. The alert payload from `alert_analysis` includes device context (hostname, OS, containment status), process tree details, and MITRE ATT&CK mapping.

### NGSIEM Custom Detections (`ngsiem:` prefix)
Custom correlation rules written in CQL that query raw EDR telemetry (ProcessRollup2, DnsRequest, NetworkConnectIP4, etc.) ingested into NGSIEM. These detections live in `resources/detections/crowdstrike/` and cover patterns like privilege escalation chains, sensor uninstalls, exfiltration tool use, and USB anomalies.

### Charlotte AI Signals (`ind:` with type=signal)
Charlotte AI generates investigation context signals that appear as `ind:` prefix alerts. These are NOT real detections — they are automated enrichment for parent `automated-lead:` alerts. They are not visible in the Falcon Detections UI and behavior retrieval fails. **Fast-track close** unless the parent `automated-lead:` alert warrants investigation.

### CWPP Container Image Scans (`cwpp:` prefix)
Container image scan findings like `SetUIDBitFoundInImage` and `ADDInstructionInDockerfile`. Generate ~89 informational alerts/day. **Bulk close** with `cwpp_noise` tag unless severity > Informational.

## Alert Type Decision Tree

| Check | Result | Action |
|-------|--------|--------|
| `type=signal` + `API Product=automated-lead-context`? | Yes | Fast-track close |
| `cwpp:` prefix + Informational severity? | Yes | Bulk close with `cwpp_noise` tag |
| `ind:` prefix (not signal)? | Yes | EDR investigation path below |
| `ngsiem:` prefix + CrowdStrike/Endpoint name? | Yes | Find template in `resources/detections/crowdstrike/`, then EDR investigation path |

## Key Fields in Alert Payload

### From `alert_analysis` (EDR IoA)
| Field | Description |
|-------|-------------|
| `device.hostname` | Endpoint hostname |
| `device.device_id` | Agent ID (aid) — GUID for all NGSIEM correlation |
| `device.platform_name` | OS: Windows, Mac, Linux |
| `device.os_version` | OS version |
| `device.containment_status` | `normal` or `contained` |
| `device.sensor_version` | Falcon sensor version |
| `behaviors[].tactic` | MITRE ATT&CK tactic |
| `behaviors[].technique` | MITRE ATT&CK technique |
| `behaviors[].filename` | Process filename that triggered |
| `behaviors[].cmdline` | Command line arguments |
| `behaviors[].parent_details.filename` | Parent process |
| `behaviors[].sha256` | File hash for IOC lookup |
| `behaviors[].user_name` | User context at trigger time |

### Raw EDR Telemetry Fields (NGSIEM)
| Field | Description | Event Types |
|-------|-------------|-------------|
| `aid` | Agent/device ID (GUID) | All EDR events |
| `ComputerName` | Hostname | All EDR events |
| `UserName` | Logged-in user at event time | ProcessRollup2, NetworkConnect |
| `#event_simpleName` | Event type discriminator (note `#` prefix) | All EDR events |
| `ImageFileName` | Full path of the executable | ProcessRollup2 |
| `CommandLine` | Process command line arguments | ProcessRollup2 |
| `ParentBaseFileName` | Parent process filename | ProcessRollup2 |
| `TargetProcessId` / `ContextProcessId` | Process ID for correlation across event types | All process events |
| `SHA256HashData` | File hash for IOC lookup | ProcessRollup2, file events |
| `DomainName` | DNS query domain | DnsRequest |
| `RemoteAddressIP4` | Destination IP | NetworkConnectIP4 |
| `RemotePort` | Destination port | NetworkConnectIP4 |
| `IntegrityLevel` | Windows process integrity (0=untrusted, 4096=low, 8192=medium, 12288=high, 16384=system) | ProcessRollup2 |

**CRITICAL:** All EDR event type fields use the `#` prefix: `#event_simpleName`, NOT `event_simpleName`. Using the unprefixed form returns 0 results silently.

## Base Query Filters

All EDR investigation queries target the `base_sensor` repo or use `aid` directly.

```cql
// Process execution telemetry
#event_simpleName=ProcessRollup2
| aid="{{device_id}}"
```

```cql
// Network connections
#event_simpleName=NetworkConnectIP4 OR #event_simpleName=NetworkConnectIP6
| aid="{{device_id}}"
```

```cql
// DNS requests
#event_simpleName=DnsRequest
| aid="{{device_id}}"
```

```cql
// File writes
#event_simpleName=NewScriptWritten OR #event_simpleName=GenericFileWritten OR #event_simpleName=RansomwareFileAccessPattern
| aid="{{device_id}}"
```

```cql
// All EDR events for a host (raw telemetry dump)
aid="{{device_id}}"
| #event_simpleName=*
| head(50)
```

**NOTE:** `endpoint_get_behaviors` is deprecated (HTTP 404 since March 2026). Use `ngsiem_query` with `aid=<device_id>` for raw EDR telemetry instead.

## Investigation Queries

### 1. Host Context (MCP Tool — Not CQL)

Call `mcp__crowdstrike__host_lookup(hostname_or_id="{{device_id_or_hostname}}")` to get:
- OS, build, sensor version
- Policy assignments
- Containment status (critical — a contained host changes urgency)
- Groups (determines applicable policies)
- Last seen timestamp
- External IP

### 2. Process Tree Around Alert Time (+-5 min)

Process execution context showing parent-child relationships near the alert timestamp.

```cql
#event_simpleName=ProcessRollup2
| aid="{{device_id}}"
| table([@timestamp, UserName, ImageFileName, CommandLine, ParentBaseFileName, SHA256HashData, IntegrityLevel], limit=100, sortby=@timestamp, order=asc)
```
**Time range:** Custom — alert timestamp +/- 5 minutes

### 3. Network Connections from Host Around Alert Time

Outbound network connections from the endpoint — look for C2, data exfiltration, or lateral movement.

```cql
#event_simpleName=NetworkConnectIP4
| aid="{{device_id}}"
| table([@timestamp, UserName, ImageFileName, RemoteAddressIP4, RemotePort, LocalAddressIP4, LocalPort], limit=100, sortby=@timestamp, order=asc)
```
**Time range:** Alert timestamp +/- 15 minutes

### 4. DNS Lookups from Host Around Alert Time

DNS resolution from the endpoint — look for C2 domain callbacks, DNS tunneling, or suspicious domain access.

```cql
#event_simpleName=DnsRequest
| aid="{{device_id}}"
| groupBy([DomainName], function=[count(as=query_count), min(@timestamp, as=first_query), max(@timestamp, as=last_query), selectLast([ComputerName, UserName, ContextBaseFileName])])
| sort(query_count, order=desc)
```
**Time range:** Alert timestamp +/- 30 minutes

### 5. File Writes by Process on Host

File creation and modification events — look for malware drops, scripts, ransomware staging.

```cql
#event_simpleName=NewScriptWritten OR #event_simpleName=GenericFileWritten OR #event_simpleName=DirectoryCreate
| aid="{{device_id}}"
| table([@timestamp, UserName, TargetFileName, ImageFileName, CommandLine], limit=100, sortby=@timestamp, order=asc)
```
**Time range:** Alert timestamp +/- 15 minutes

### 6. Login History (MCP Tool)

Call `mcp__crowdstrike__host_login_history(device_id="{{device_id}}")` to determine:
- Who logged into the endpoint before and after the alert
- Login type (local, remote, interactive, network)
- Whether the attacker's user context matches the expected user

### 7. User's Other Devices

If the alert involves a specific user, check if the same behavior occurred on their other devices.

```cql
#event_simpleName=ProcessRollup2
| UserName="{{username}}"
| aid!="{{device_id}}"
| groupBy([aid, ComputerName], function=[count(as=process_count), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(process_count, order=desc)
```
**Time range:** 24h

Also call `mcp__crowdstrike__host_lookup(hostname_or_id="{{username}}")` to find all devices associated with this user.

### 8. Cross-Source Correlation (24h)

Check the user's activity across all platforms — EntraID, AWS, SASE/VPN, Google.

```cql
"{{user_email}}"
| #repo!="xdr*"
| table([@timestamp, #Vendor, #Product, #event.dataset, event.action, source.ip, #event.outcome], limit=100, sortby=@timestamp, order=desc)
```
**Time range:** 24h centered on alert timestamp

**Identity mapping:** EDR `UserName` is typically `DOMAIN\jdoe` or just `jdoe`. Map to email (`jdoe@example.com`) for cross-source queries. The `$identity_enrich_from_email()` saved search can help with cross-platform resolution.

## Triage Checklist

1. **What alert type?** Check the composite ID prefix and alert type field. `ind:` with `type=signal` = Charlotte AI (fast-track). `cwpp:` = container scan (bulk close). Otherwise proceed.
2. **Get host context:** Call `host_lookup(device_id)` — OS, containment status, sensor version, groups, policies. A contained host changes the urgency.
3. **Who is the user?** Map `UserName` to an employee. Check role — IT admin running PowerShell is different from a sales rep running PowerShell.
4. **What is the process?** Check `ImageFileName`, `CommandLine`, `ParentBaseFileName`. Is this a known LOLBin (cmd, powershell, wscript, mshta, certutil, rundll32)? Is the parent process expected?
5. **Is the binary signed?** Check `SHA256HashData` against known-good hashes. Unsigned binaries from `%TEMP%` or `%APPDATA%` are suspicious.
6. **Was there network activity?** Check queries 3 and 4 for outbound connections and DNS lookups around the alert time. C2 callbacks are high-priority.
7. **Was there file activity?** Check query 5 for dropped files, scripts, or encrypted file patterns.
8. **Who else was on the box?** Check `host_login_history` for other users — lateral movement indicator.
9. **Same behavior on other devices?** Check query 7 — same user, different device = credential compromise. Different user, same technique = campaign.
10. **Cross-platform check:** Run query 8 — did EntraID, AWS, SASE/VPN, or Google see activity from this user/IP around the same time?

## Common FP Patterns

| FP Pattern | How to Identify | Resolution |
|---|---|---|
| Charlotte AI signals | `type: signal`, `API Product: automated-lead-context`, behavior retrieval fails | Fast-track close unless parent `automated-lead:` alert is TP |
| CWPP container image scans | `cwpp:` prefix, `SetUIDBitFoundInImage`, `ADDInstructionInDockerfile`, Informational severity | Bulk close with `cwpp_noise` tag |
| Legitimate software installs | Approved vendor, signed binary, IT ticket matches timing | Close FP, no tuning needed |
| WinRAR from explorer.exe | `ParentBaseFileName=explorer.exe`, user double-clicked archive | Already tuned — excluded explorer parent in `crowdstrike_endpoint_potential_exfiltration_tools_detected.yaml` |
| USB personal media | Date-stamped MP4/media files, external consumer drive, no corporate data paths | Close FP — personal use. Verify file types and paths. |
| EC2 IMDS credential retrieval | Jumphost querying own role via IMDSv2, python/SDK parent process, two-step lookup pattern | Known AWS infra pattern — SSM agent credential refresh |
| New device OOBE | Device first seen <30d, no Entra join, `UserOOBEBroker.exe` activity, high logon count (20+) | FP but surface compliance finding to IT — device needs Entra join |
| RMM management commands | `ParentBaseFileName=<rmm_service>.exe` or `<rmm_remote>.exe`, config-mgmt/network reset/app launch commands | Excluded in privilege escalation detection. Known IT management tool. |
| OEM telemetry agent | `ParentBaseFileName=<oem_telemetry_agent>.exe` | Excluded in privilege escalation detection. OEM management. |

## Classification Guidance

| Signal | Likely FP | Likely TP |
|--------|-----------|-----------|
| Process origin | Signed binary, known vendor, expected parent (explorer, services) | Unsigned, temp path, LOLBin chain (cmd→powershell→certutil) |
| Command line | Standard flags, short, no encoding | Base64 encoded, `-enc`, `-nop`, download cradles, AMSI bypass |
| Network activity | No outbound connections from process | C2 callback, beaconing pattern, unusual port |
| File activity | No file drops or script writes | Dropped executables, scripts in %TEMP%, encrypted files |
| User context | IT admin, expected for their role | Non-admin running admin tools, service account on workstation |
| Time | Business hours, matches user's location | Off-hours with no business justification |
| Device | Corporate-managed, domain-joined, current sensor | Unmanaged, no Entra registration, outdated sensor |
| Lateral indicators | Single device, no cross-source anomalies | Same technique on multiple hosts, cross-platform credential use |

## Closing the Alert

**Fast-track (Charlotte AI signals):**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="Fast-track close — Charlotte AI signal, not a real detection",
  tags=["false_positive", "charlotte_ai_signal"]
)
```

**Fast-track (CWPP image scans):**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="Bulk close — CWPP container image scan, informational",
  tags=["false_positive", "cwpp_noise"]
)
```

**FP — EDR IoA:**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="FP — <reason>. EDR IoA, not tunable in NGSIEM.",
  tags=["false_positive", "endpoint"]
)
```

**FP — NGSIEM Custom:**
```
mcp__crowdstrike__update_alert_status(
  status="closed",
  comment="FP — <reason>. Tuned: <description>",
  tags=["false_positive", "tuned"]
)
```
Then proceed to Phase 3B to edit the detection template in `resources/detections/crowdstrike/`.

**TP:**
Escalate via Phase 3C workflow.
```
mcp__crowdstrike__update_alert_status(
  status="in_progress",
  comment="TP confirmed: <summary>",
  tags=["true_positive"]
)
```
For endpoint TPs, also check containment status via `host_lookup` and reference RTR scripts in `.claude/skills/soc-respond/rtr-reference.md` for available response actions.

## Enrichment Functions (Currently None)

CrowdStrike endpoint has 0 enrichment functions. Until these are built, investigation queries must manually extract host context via the `host_lookup` MCP tool and raw NGSIEM queries.

Future candidates:
- `$crowdstrike_enrich_host_context()` — host risk tier, OS, group membership, sensor version
- `$crowdstrike_classify_process_type()` — LOLBin detection, signed/unsigned, first-seen analysis

## Platform-Specific Caveats

- **`endpoint_get_behaviors` is deprecated (HTTP 404 since March 2026).** Use `ngsiem_query` with `aid=<device_id>` against raw EDR telemetry instead.
- **`#event_simpleName` requires the `#` prefix.** The unprefixed `event_simpleName` returns 0 results silently.
- **EDR `UserName` format:** `DOMAIN\jdoe` or `jdoe` (local). NOT email. Map to email manually for cross-source queries.
- **Process IDs:** Use `TargetProcessId` and `ContextProcessId` to correlate across event types (ProcessRollup2 → NetworkConnectIP4 → DnsRequest).
- **`selfJoinFilter` for complex correlations:** Many NGSIEM endpoint detections use `selfJoinFilter(field=[aid], where=[...])` to join multiple event types. When investigating detection logic, read the template CQL to understand the join conditions.
