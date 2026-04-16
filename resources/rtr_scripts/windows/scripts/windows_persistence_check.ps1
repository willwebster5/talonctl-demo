# Windows Persistence Detection Script
# Version: 1.0
# Purpose: Malware persistence identification

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Windows Persistence Check" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# 1. Startup Folders
Write-Host "[+] Startup Folder Items" -ForegroundColor Green
Write-Host "  [*] Current User Startup:"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
  Select-Object Name, FullName, LastWriteTime | Format-Table -AutoSize

Write-Host "  [*] All Users Startup:"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
  Select-Object Name, FullName, LastWriteTime | Format-Table -AutoSize
Write-Host ""

# 2. Registry Run Keys
Write-Host "[+] Registry Run Keys" -ForegroundColor Green

Write-Host "  [*] HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
  Format-List

Write-Host "  [*] HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue |
  Format-List

Write-Host "  [*] HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
  Format-List

Write-Host "  [*] HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue |
  Format-List
Write-Host ""

# 3. Scheduled Tasks (Recently Created)
Write-Host "[+] Scheduled Tasks (Created in Last 30 Days)" -ForegroundColor Green
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-30)} |
  Select-Object TaskName, TaskPath, State, @{Name="Author";Expression={$_.Principal.UserId}} |
  Format-Table -AutoSize -Wrap
Write-Host ""

# 4. Services (Non-Microsoft)
Write-Host "[+] Non-Microsoft Services" -ForegroundColor Green
Get-WmiObject Win32_Service |
  Where-Object {$_.PathName -notmatch "C:\\Windows" -and $_.PathName -notmatch "C:\\Program Files"} |
  Select-Object Name, DisplayName, State, StartMode, PathName |
  Format-Table -AutoSize -Wrap
Write-Host ""

# 5. WMI Event Subscriptions (Potential Persistence)
Write-Host "[+] WMI Event Consumers (Persistence Mechanism)" -ForegroundColor Green
Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue |
  Select-Object Name, @{Name="Type";Expression={$_.__CLASS}} |
  Format-Table -AutoSize
Write-Host ""

# 6. AppInit DLLs (DLL Injection)
Write-Host "[+] AppInit DLLs (Potential DLL Injection)" -ForegroundColor Green
$appInit = Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
if ($appInit.AppInit_DLLs) {
    Write-Host "  [!] AppInit_DLLs found: $($appInit.AppInit_DLLs)" -ForegroundColor Yellow
} else {
    Write-Host "  [OK] No AppInit_DLLs configured" -ForegroundColor Green
}
Write-Host ""

# 7. Recently Modified Files in System32
Write-Host "[+] Recently Modified Files in System32 (Last 7 Days)" -ForegroundColor Green
Get-ChildItem C:\Windows\System32 -File -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
  Select-Object Name, LastWriteTime, Length |
  Sort-Object LastWriteTime -Descending |
  Format-Table -AutoSize
Write-Host ""

# 8. User Accounts (Recently Created)
Write-Host "[+] User Accounts Created in Last 30 Days" -ForegroundColor Green
Get-LocalUser | Where-Object {$_.Enabled -eq $true} |
  Select-Object Name, Enabled, LastLogon, @{Name="PasswordLastSet";Expression={$_.PasswordLastSet}} |
  Format-Table -AutoSize
Write-Host ""

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Persistence Check Complete" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
