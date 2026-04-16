# Windows Process Investigation Script
# Version: 1.0
# Purpose: IR triage and process analysis

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Windows Process Investigation" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# 1. Running Processes with Command Lines
Write-Host "[+] Running Processes with Command Lines" -ForegroundColor Green
Get-WmiObject Win32_Process | Select-Object ProcessId, Name, @{Name="CommandLine";Expression={$_.CommandLine -replace '\s+', ' '}}, @{Name="ParentPID";Expression={$_.ParentProcessId}} |
  Format-Table -AutoSize -Wrap

Write-Host ""

# 2. Network Connections by Process
Write-Host "[+] Active Network Connections" -ForegroundColor Green
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).Name}} |
  Format-Table -AutoSize

Write-Host ""

# 3. Suspicious PowerShell Processes and Loaded Modules
Write-Host "[+] PowerShell Processes and Loaded DLLs" -ForegroundColor Green
$psProcesses = Get-Process | Where-Object {$_.Name -like "*powershell*"}
if ($psProcesses) {
    foreach ($proc in $psProcesses) {
        Write-Host "  Process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Yellow
        $proc | Select-Object -ExpandProperty Modules |
          Select-Object ModuleName, FileName |
          Format-Table -AutoSize
    }
} else {
    Write-Host "  No PowerShell processes found" -ForegroundColor Gray
}

Write-Host ""

# 4. Recently Created Processes
Write-Host "[+] Recently Started Processes (Last 10)" -ForegroundColor Green
Get-Process | Sort-Object StartTime -Descending | Select-Object -First 10 |
  Select-Object Name, Id, StartTime, @{Name="Path";Expression={$_.Path}} |
  Format-Table -AutoSize

Write-Host ""

# 5. Running Services (Started)
Write-Host "[+] Running Services" -ForegroundColor Green
Get-Service | Where-Object {$_.Status -eq 'Running'} |
  Select-Object Name, DisplayName, Status |
  Format-Table -AutoSize

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Investigation Complete" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
