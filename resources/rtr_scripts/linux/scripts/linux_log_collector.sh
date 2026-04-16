#!/bin/bash
# Linux Log Collection Script
# Version: 1.0
# Purpose: IR triage and log analysis

echo "=================================="
echo "Linux Log Collection"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Hostname: $(hostname)"
echo "=================================="
echo ""

# 1. Recent Auth Logs
echo "[+] Recent Authentication Logs (Last 100 entries)"
if [ -f /var/log/auth.log ]; then
    tail -100 /var/log/auth.log
elif [ -f /var/log/secure ]; then
    tail -100 /var/log/secure
else
    echo "  [!] Auth log not found (checked /var/log/auth.log and /var/log/secure)"
fi
echo ""

# 2. Failed Login Attempts
echo "[+] Failed Login Attempts (Last 50)"
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | tail -50
elif [ -f /var/log/secure ]; then
    grep "Failed password" /var/log/secure | tail -50
else
    echo "  [!] Auth log not found"
fi
echo ""

# 3. Successful Root Logins
echo "[+] Successful Root Logins"
if [ -f /var/log/auth.log ]; then
    grep "Accepted" /var/log/auth.log | grep "root" | tail -20
elif [ -f /var/log/secure ]; then
    grep "Accepted" /var/log/secure | grep "root" | tail -20
else
    echo "  [!] Auth log not found"
fi
echo ""

# 4. Active User Sessions
echo "[+] Currently Logged In Users"
who -H
echo ""

# 5. Recently Modified Files in /tmp
echo "[+] Recently Modified Files in /tmp (Last 24 hours)"
find /tmp -type f -mtime -1 -ls 2>/dev/null | head -50
echo ""

# 6. Recently Modified Files in /var/tmp
echo "[+] Recently Modified Files in /var/tmp (Last 24 hours)"
find /var/tmp -type f -mtime -1 -ls 2>/dev/null | head -50
echo ""

# 7. Cron Jobs for Current User
echo "[+] Cron Jobs for Current User"
crontab -l 2>/dev/null || echo "  No crontab for current user"
echo ""

# 8. System Cron Jobs
echo "[+] System Cron Jobs (/etc/cron.d/)"
ls -la /etc/cron.d/ 2>/dev/null || echo "  /etc/cron.d/ not accessible"
echo ""

# 9. Recently Installed Packages (Debian/Ubuntu)
if command -v dpkg &> /dev/null; then
    echo "[+] Recently Installed Packages (Last 20)"
    grep " install " /var/log/dpkg.log 2>/dev/null | tail -20
    echo ""
fi

# 10. Recently Installed Packages (RedHat/CentOS)
if command -v rpm &> /dev/null; then
    echo "[+] Recently Installed Packages (Last 20)"
    rpm -qa --last | head -20
    echo ""
fi

echo "=================================="
echo "Log Collection Complete"
echo "=================================="
