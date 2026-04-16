# Windows Network Connection Analysis
# Version: 1.0
# Purpose: C2 detection and network analysis test

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Network Connection Analysis" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# 1. Established TCP Connections
Write-Host "[+] Established TCP Connections" -ForegroundColor Green
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
    @{Name="PID";Expression={$_.OwningProcess}} |
  Sort-Object RemoteAddress |
  Format-Table -AutoSize

Write-Host ""

# 2. Listening TCP Ports
Write-Host "[+] Listening TCP Ports" -ForegroundColor Green
Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress, LocalPort,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
    @{Name="PID";Expression={$_.OwningProcess}} |
  Sort-Object LocalPort |
  Format-Table -AutoSize

Write-Host ""

# 3. External Connections (Non-Private IPs)
Write-Host "[+] Connections to External IPs (Non-RFC1918)" -ForegroundColor Green
Get-NetTCPConnection -State Established |
  Where-Object {
    $_.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' -and
    $_.RemoteAddress -notmatch '^(::1|fe80::|fc00::)'
  } |
  Select-Object RemoteAddress, RemotePort,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
    @{Name="PID";Expression={$_.OwningProcess}},
    @{Name="Path";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
  Format-Table -AutoSize -Wrap

Write-Host ""

# 4. UDP Endpoints
Write-Host "[+] UDP Endpoints" -ForegroundColor Green
Get-NetUDPEndpoint |
  Select-Object LocalAddress, LocalPort,
    @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}},
    @{Name="PID";Expression={$_.OwningProcess}} |
  Sort-Object LocalPort |
  Format-Table -AutoSize

Write-Host ""

# 5. DNS Client Cache (Recent Lookups)
Write-Host "[+] DNS Client Cache (Recent Lookups)" -ForegroundColor Green
Get-DnsClientCache |
  Select-Object Entry, Data, TimeToLive |
  Sort-Object Entry |
  Format-Table -AutoSize

Write-Host ""

# 6. Network Adapter Configuration
Write-Host "[+] Network Adapter Configuration" -ForegroundColor Green
Get-NetIPConfiguration |
  Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer |
  Format-Table -AutoSize

Write-Host ""

# 7. NetStat Summary
Write-Host "[+] Connection State Summary" -ForegroundColor Green
Get-NetTCPConnection | Group-Object State |
  Select-Object Name, Count |
  Sort-Object Count -Descending |
  Format-Table -AutoSize

Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Network Analysis Complete" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
