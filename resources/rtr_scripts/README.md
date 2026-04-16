# RTR Custom Scripts

This directory contains CrowdStrike Real-Time Response (RTR) custom scripts managed as Infrastructure as Code.

## Overview

RTR custom scripts are PowerShell, Bash, or Python scripts that can be executed on endpoints during incident response using the RTR `runscript` command. These scripts enable automated investigation and remediation tasks.

## Template Format

RTR script templates use YAML format with the following structure:

```yaml
name: script_name
description: |
  Detailed description of what the script does,
  when to use it, and any prerequisites
platform:
  - windows    # Required - can be: windows, linux, mac (array for multi-platform)
  - linux
permission_type: group  # Optional - private, group (default), or public
content: |
  # PowerShell script content for Windows
  Get-Process | Select-Object Name, Id, Path

  # Or Bash/Python content for Linux/Mac
comments_for_audit_log: Optional audit trail comment
```

## Platform Support

- **windows**: PowerShell scripts (.ps1)
- **linux**: Bash scripts (.sh) or Python scripts (.py)
- **mac**: Bash scripts (.sh) or Python scripts (.py)

Scripts can target multiple platforms by listing them in the `platform` array.

## Permission Types

- **private**: Only visible to the user who uploaded it
- **group**: Visible to all RTR administrators (default)
- **public**: Visible to all active-responders and RTR admins

## Content Options

### External File Reference (Recommended)
Store scripts in separate `.ps1` or `.sh` files for better tooling support:

```yaml
name: windows_process_investigation
description: Collect detailed process information
platform:
  - windows
permission_type: group
file_path: ./scripts/windows_process_investigation.ps1
comments_for_audit_log: IR script for process investigation
```

**Benefits of external files:**
- ✅ **Syntax highlighting** in your IDE/editor
- ✅ **Linting and error checking** (PSScriptAnalyzer for PowerShell, ShellCheck for Bash)
- ✅ **Better git diffs** - changes show as script diffs, not YAML diffs
- ✅ **Easy testing** - run scripts directly: `powershell -File script.ps1`
- ✅ **Cleaner templates** - YAML contains only metadata, not code

### Inline Content (Simple Scripts)
For short, simple scripts, you can embed content directly in the YAML:

```yaml
name: simple_check
description: Quick environment check
platform:
  - windows
permission_type: group
content: |
  # Simple one-liner scripts
  Get-Process | Select-Object Name, Id | Format-Table
comments_for_audit_log: Simple environment check
```

**Use inline content when:**
- Script is < 20 lines
- Script is platform-agnostic or very simple
- Quick one-off scripts that don't need testing

## Directory Structure

```
resources/rtr_scripts/
├── README.md                                  # This file
├── scripts/                                   # Actual script files (.ps1, .sh)
│   ├── windows_process_investigation.ps1
│   ├── linux_log_collector.sh
│   ├── windows_network_connections.ps1
│   ├── linux_process_enumeration.sh
│   └── windows_persistence_check.ps1
├── windows_process_investigation.yaml         # Template (references .ps1)
├── linux_log_collector.yaml                   # Template (references .sh)
├── windows_network_connections.yaml           # Template (references .ps1)
├── linux_process_enumeration.yaml             # Template (references .sh)
└── windows_persistence_check.yaml             # Template (references .ps1)
```

## Example Templates

### Windows Investigation Script (External File)
**Template:** `windows_process_investigation.yaml`
```yaml
name: windows_process_investigation
description: |
  Comprehensive process investigation script for Windows endpoints.

  Collects:
  - Running processes with full command lines
  - Network connections by process
  - Loaded DLLs and modules for suspicious processes
  - Process parent-child relationships
  - Services and scheduled tasks
platform:
  - windows
permission_type: group
file_path: ./scripts/windows_process_investigation.ps1
comments_for_audit_log: IR process investigation script
```

**Script:** `scripts/windows_process_investigation.ps1`
```powershell
# Windows Process Investigation Script
# Version: 1.0

Write-Host "Windows Process Investigation" -ForegroundColor Cyan

# Get process details with command line
Get-WmiObject Win32_Process |
  Select-Object ProcessId, Name, CommandLine |
  Format-Table -AutoSize

# Get network connections
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort |
  Format-Table -AutoSize
```

### Linux Log Collection Script (External File)
**Template:** `linux_log_collector.yaml`
```yaml
name: linux_log_collector
description: |
  Linux log collection script for incident response triage.

  Collects authentication logs and suspicious activity indicators.
platform:
  - linux
permission_type: group
file_path: ./scripts/linux_log_collector.sh
comments_for_audit_log: IR log collection script
```

**Script:** `scripts/linux_log_collector.sh`
```bash
#!/bin/bash
# Linux Log Collection Script

echo "=== Recent Auth Logs ==="
tail -100 /var/log/auth.log

echo "=== Failed Login Attempts ==="
grep "Failed password" /var/log/auth.log | tail -50

echo "=== Recently Modified Files in /tmp ==="
find /tmp -type f -mtime -1 -ls
```

## Deployment Workflow

### 1. Plan Changes
```bash
# Review what will be deployed
python scripts/resource_deploy.py plan --resources=rtr_script
```

### 2. Apply Changes
```bash
# Deploy RTR scripts to CrowdStrike
python scripts/resource_deploy.py apply --resources=rtr_script --auto-approve
```

### 3. Sync State
```bash
# Synchronize local state with CrowdStrike
python scripts/resource_deploy.py sync --resources=rtr_script
```

## CI/CD Integration

RTR scripts can be automatically deployed via GitHub Actions when templates are modified:

```yaml
# .github/workflows/deploy-rtr.yml
name: Deploy RTR Resources
on:
  push:
    paths:
      - 'resources/rtr_scripts/**'
      - 'resources/rtr_put_files/**'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy RTR Scripts
        run: |
          python scripts/resource_deploy.py plan --resources=rtr_script,rtr_put_file
          python scripts/resource_deploy.py apply --resources=rtr_script,rtr_put_file --auto-approve
```

## Best Practices

### Security
- **Never include credentials** in script content
- **Review scripts** before deployment - they execute with system-level privileges
- **Use permission_type: group** for shared IR scripts
- **Use permission_type: private** for experimental/untested scripts

### Documentation
- Provide detailed descriptions explaining what the script does
- Document prerequisites (e.g., "Requires PowerShell 5.1+")
- Include expected output format
- Add comments within script content

### Naming
- Use descriptive names: `windows_memory_dump` not `memdump`
- Include platform in name if platform-specific: `linux_network_capture`
- Use underscores, not hyphens: `collect_logs` not `collect-logs`

### Testing
- Test scripts in lab environment before production deployment
- Verify scripts work on target OS versions
- Check performance impact (CPU, memory, network)
- Test on endpoints with limited privileges

## Incident Response Workflow

1. **Detection Alert**: Security analyst receives detection alert
2. **RTR Session**: Analyst opens RTR session to affected endpoint
3. **Run Script**: Execute investigation script:
   ```
   runscript -CloudFile=windows_process_investigation
   ```
4. **Analyze Output**: Review script output for IOCs
5. **Containment**: Execute remediation script if needed
6. **Document**: Log actions in incident ticket

## Common Use Cases

### Investigation Scripts
- Process enumeration and analysis
- Network connection mapping
- File system timeline analysis
- Registry key inspection (Windows)
- Log collection and parsing

### Containment Scripts
- Kill suspicious processes
- Block network connections
- Quarantine files
- Disable user accounts

### Collection Scripts
- Memory dump acquisition
- Forensic artifact collection
- Configuration backups
- Evidence preservation

## Limitations

- **Script Size**: Maximum 5MB per script
- **Execution Time**: Scripts timeout after 10 minutes by default
- **Platform Support**: Cannot execute cross-platform (Windows script won't run on Linux)
- **No Updates**: Scripts are immutable - changes create a new version with different ID

## Troubleshooting

### Script Not Found
- Verify script is deployed: check CrowdStrike Falcon UI > Response Scripts
- Check permission_type: may not be visible to current user
- Sync state: `python scripts/resource_deploy.py sync --resources=rtr_script`

### Script Execution Fails
- Check platform compatibility
- Verify RTR Admin privileges
- Review script syntax and error messages
- Test script manually in PowerShell/Bash first

### Deployment Errors
- Validate template: `python scripts/resource_deploy.py validate --resources=rtr_script`
- Check API credentials and permissions
- Review falconpy logs for API errors

## Additional Resources

- [CrowdStrike RTR Documentation](https://falcon.crowdstrike.com/documentation/page/real-time-response)
- [RTR Command Reference](https://falcon.crowdstrike.com/documentation/page/rtr-commands)
- [FalconPy RTR Admin API](https://falconpy.io/Service-Collections/Real-Time-Response-Admin.html)
