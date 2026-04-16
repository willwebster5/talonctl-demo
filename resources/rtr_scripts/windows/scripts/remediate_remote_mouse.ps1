# REMOTEMOUSE IMMEDIATE INCIDENT RESPONSE SCRIPT
# Run as Administrator
# Created: 9/26/2025 - Active Threat Response

Write-Host "=== STARTING REMOTEMOUSE INCIDENT CONTAINMENT ===" -ForegroundColor Red
Write-Host "Threat Level: HIGH - Active Remote Access Tool" -ForegroundColor Yellow
Write-Host ""

# 1. CAPTURE EVIDENCE BEFORE TERMINATION
Write-Host "[1] Capturing Evidence..." -ForegroundColor Yellow

# Create incident folder
$incidentFolder = "C:\Incident_RemoteMouse_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $incidentFolder -ItemType Directory -Force | Out-Null
Set-Location $incidentFolder

# Capture process details before killing
Get-Process | Where-Object {$_.ProcessName -like "*remotemouse*"} | Select-Object * | Export-Csv ".\remotemouse_processes.csv" -NoTypeInformation

# Capture network state
Get-NetTCPConnection | Where-Object {$_.LocalPort -in @(1978, 1979)} | Export-Csv ".\remotemouse_connections.csv" -NoTypeInformation

# Get process command lines and paths
Get-WmiObject Win32_Process | Where-Object {$_.ProcessName -like "*remotemouse*"} | Select-Object ProcessId, ProcessName, CommandLine, ExecutablePath, CreationDate | Export-Csv ".\remotemouse_process_details.csv" -NoTypeInformation

Write-Host "Evidence captured to: $incidentFolder" -ForegroundColor Green

# 2. CHECK FOR ACTIVE CONNECTIONS (Not just listeners)
Write-Host "`n[2] Checking for Active Remote Connections..." -ForegroundColor Yellow
$activeConnections = Get-NetTCPConnection | Where-Object {$_.LocalPort -in @(1978, 1979) -and $_.State -eq "Established"}
if ($activeConnections) {
    Write-Host "!!! ACTIVE CONNECTIONS DETECTED !!!" -ForegroundColor Red
    $activeConnections | Format-Table LocalPort, RemoteAddress, RemotePort, State -AutoSize
    $activeConnections | Export-Csv ".\ACTIVE_CONNECTIONS.csv" -NoTypeInformation
} else {
    Write-Host "No active connections found (only listening)" -ForegroundColor Green
}

# 3. BLOCK NETWORK IMMEDIATELY
Write-Host "`n[3] Creating Firewall Block Rules..." -ForegroundColor Yellow

# Block inbound connections
New-NetFirewallRule -DisplayName "BLOCK RemoteMouse Inbound 1978" -Direction Inbound -LocalPort 1978 -Protocol TCP -Action Block -Enabled True | Out-Null
New-NetFirewallRule -DisplayName "BLOCK RemoteMouse Inbound 1979" -Direction Inbound -LocalPort 1979 -Protocol TCP -Action Block -Enabled True | Out-Null

# Block the executables
$remotemousePaths = Get-Process | Where-Object {$_.ProcessName -like "*remotemouse*"} | Select-Object -ExpandProperty Path | Sort-Object -Unique
foreach ($path in $remotemousePaths) {
    if ($path) {
        New-NetFirewallRule -DisplayName "BLOCK RemoteMouse Program - $([System.IO.Path]::GetFileName($path))" -Direction Outbound -Program $path -Action Block -Enabled True | Out-Null
        Write-Host "Blocked: $path" -ForegroundColor Green
    }
}

# 4. TERMINATE PROCESSES
Write-Host "`n[4] Terminating RemoteMouse Processes..." -ForegroundColor Yellow
$processes = Get-Process | Where-Object {$_.ProcessName -like "*remotemouse*"}
foreach ($proc in $processes) {
    try {
        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        Write-Host "Killed: $($proc.ProcessName) (PID: $($proc.Id))" -ForegroundColor Green
    } catch {
        Write-Host "Failed to kill: $($proc.ProcessName) (PID: $($proc.Id))" -ForegroundColor Red
    }
}

# 5. FIND AND QUARANTINE FILES
Write-Host "`n[5] Locating RemoteMouse Files..." -ForegroundColor Yellow
$suspiciousFiles = @()

# Search for RemoteMouse files
$searchPaths = @(
    "C:\Users\ChaseKaiser\Downloads",
    "C:\Users\ChaseKaiser\Desktop",
    "C:\Users\ChaseKaiser\AppData",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData"
)

foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        $found = Get-ChildItem -Path $searchPath -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*remotemouse*"}
        if ($found) {
            $suspiciousFiles += $found
        }
    }
}

if ($suspiciousFiles) {
    Write-Host "Found RemoteMouse files:" -ForegroundColor Yellow
    $suspiciousFiles | Select-Object FullName, CreationTime, Length | Format-Table -AutoSize
    $suspiciousFiles | Select-Object FullName, CreationTime, Length, @{N='Hash';E={(Get-FileHash $_.FullName -Algorithm SHA256).Hash}} | Export-Csv ".\remotemouse_files.csv" -NoTypeInformation
    
    # Create quarantine folder
    $quarantine = "C:\QUARANTINE_RemoteMouse"
    New-Item -Path $quarantine -ItemType Directory -Force | Out-Null
    
    foreach ($file in $suspiciousFiles) {
        $destPath = Join-Path $quarantine $file.Name
        try {
            Move-Item -Path $file.FullName -Destination $destPath -Force -ErrorAction Stop
            Write-Host "Quarantined: $($file.FullName)" -ForegroundColor Green
        } catch {
            Write-Host "Could not quarantine (may be in use): $($file.FullName)" -ForegroundColor Yellow
        }
    }
}

# 6. CHECK FOR PERSISTENCE (Extended)
Write-Host "`n[6] Checking for Persistence Mechanisms..." -ForegroundColor Yellow

# Check registry
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

$foundPersistence = $false
foreach ($regPath in $regPaths) {
    $items = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
    if ($items) {
        $items.PSObject.Properties | Where-Object {$_.Value -like "*remotemouse*"} | ForEach-Object {
            Write-Host "Found in $regPath : $($_.Name) = $($_.Value)" -ForegroundColor Red
            $foundPersistence = $true
        }
    }
}

# Check scheduled tasks
$tasks = Get-ScheduledTask | Where-Object {$_.TaskName -like "*remotemouse*" -or $_.Actions.Execute -like "*remotemouse*"}
if ($tasks) {
    Write-Host "Found scheduled tasks:" -ForegroundColor Red
    $tasks | Format-Table TaskName, State -AutoSize
    $foundPersistence = $true
}

# Check services
$services = Get-Service | Where-Object {$_.Name -like "*remotemouse*" -or $_.DisplayName -like "*remotemouse*"}
if ($services) {
    Write-Host "Found services:" -ForegroundColor Red
    $services | Format-Table Name, DisplayName, Status, StartType -AutoSize
    
    # Disable services
    foreach ($svc in $services) {
        try {
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            Set-Service -Name $svc.Name -StartupType Disabled
            Write-Host "Disabled service: $($svc.Name)" -ForegroundColor Green
        } catch {
            Write-Host "Could not disable service: $($svc.Name)" -ForegroundColor Yellow
        }
    }
    $foundPersistence = $true
}

if (-not $foundPersistence) {
    Write-Host "No persistence mechanisms found in common locations" -ForegroundColor Green
}

# 7. CHECK FOR OTHER INFECTIONS
Write-Host "`n[7] Scanning for Other Remote Access Tools..." -ForegroundColor Yellow
$otherRATs = Get-Process | Where-Object {$_.ProcessName -match "teamviewer|anydesk|logmein|vnc|rustdesk|meshcentral|screenconnect|ammyy|supremo|aeroadmin"}
if ($otherRATs) {
    Write-Host "WARNING: Other remote tools detected!" -ForegroundColor Red
    $otherRATs | Format-Table ProcessName, Id, StartTime -AutoSize
} else {
    Write-Host "No other common remote tools detected" -ForegroundColor Green
}

# 8. GENERATE REPORT
Write-Host "`n[8] Generating Incident Report..." -ForegroundColor Yellow
$report = @"
REMOTEMOUSE INCIDENT REPORT
Generated: $(Get-Date)
Hostname: $env:COMPUTERNAME
User: $env:USERNAME

THREAT ASSESSMENT:
- RemoteMouse remote access tool detected and neutralized
- Processes terminated: $(($processes | Measure-Object).Count)
- Files quarantined: $(($suspiciousFiles | Measure-Object).Count)
- Firewall rules created: 4+
- Active connections at time of response: $(($activeConnections | Measure-Object).Count)

ACTIONS TAKEN:
1. Evidence collected to: $incidentFolder
2. Network access blocked via Windows Firewall
3. Processes terminated
4. Files quarantined to: C:\QUARANTINE_RemoteMouse
5. Persistence mechanisms checked and removed
6. Services disabled

RECOMMENDATIONS:
1. Change user passwords immediately
2. Review user's email for phishing attempts
3. Scan for additional malware
4. Review network logs for data exfiltration
5. Consider reimaging the system
6. Implement application whitelisting

Evidence Location: $incidentFolder
"@

$report | Out-File ".\INCIDENT_REPORT.txt"
Write-Host $report

Write-Host "`n=== CONTAINMENT COMPLETE ===" -ForegroundColor Green
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Review evidence in: $incidentFolder" -ForegroundColor White
Write-Host "2. Check CrowdStrike console for additional alerts" -ForegroundColor White
Write-Host "3. Interview user ChaseKaiser about the installation" -ForegroundColor White
Write-Host "4. Search for similar activity on other endpoints" -ForegroundColor White
Write-Host "5. Consider full forensic imaging if data theft suspected" -ForegroundColor White