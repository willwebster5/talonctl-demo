# PCAPPSTORE ADWARE REMOVAL SCRIPT
# Run as Administrator
# Description: Removes PCAppStore adware and all associated components

# Load RTR Log Helper functions
# Try relative path first (local dev), then deployed path (RTR dispatch)
$helperPath = "$PSScriptRoot\..\common\RTR-LogHelper.ps1"
if (-not (Test-Path $helperPath)) {
    $helperPath = "C:\CrowdStrike\RTR-LogHelper.ps1"
}
if (Test-Path $helperPath) {
    . $helperPath
} else {
    Write-Warning "RTR-LogHelper.ps1 not found. Run with --with-logging to deploy it first."
}

Write-Host "=== STARTING PCAPPSTORE ADWARE REMOVAL ===" -ForegroundColor Cyan
Write-Host "Threat Type: Adware/PUP - Search Engine Hijacker" -ForegroundColor Yellow
Write-Host ""

# Initialize RTR logging
$logFile = Initialize-RTRLogging -ScriptName "PCAppStore_Removal"
$removedItems = @()

# Wrapper function for backward compatibility
function Write-Log {
    param($Message, $Color = "White")
    Write-RTRLog -Message $Message -LogFile $logFile -Level "INFO"
    Write-Host $Message -ForegroundColor $Color
}

Write-Log "Starting PCAppStore removal process..." "Cyan"
Write-Log "Log file: $logFile" "Gray"

# 1. TERMINATE MALICIOUS PROCESSES
Write-Log "`n[1] Terminating PCAppStore Processes..." "Yellow"

$processNames = @("PCAppStore", "nwjs", "PCapp", "NW_store", "PCAppStore.exe", "PCapp.exe", "NW_store.exe")
$killedProcesses = 0

foreach ($procName in $processNames) {
    $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($processes) {
        foreach ($proc in $processes) {
            try {
                Write-Log "  Terminating: $($proc.ProcessName) (PID: $($proc.Id), Path: $($proc.Path))" "Yellow"
                Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                $removedItems += "Process: $($proc.ProcessName) (PID: $($proc.Id))"
                $killedProcesses++
                Write-Log "  Successfully terminated $($proc.ProcessName)" "Green"
            } catch {
                Write-Log "  Failed to terminate $($proc.ProcessName): $($_.Exception.Message)" "Red"
            }
        }
    }
}

if ($killedProcesses -eq 0) {
    Write-Log "  No PCAppStore processes found running" "Green"
}

# 2. REMOVE FOLDERS FROM USER PROFILES
Write-Log "`n[2] Removing PCAppStore Folders..." "Yellow"

$userProfiles = Get-ChildItem C:\Users -ErrorAction SilentlyContinue
$foldersRemoved = 0

foreach ($userProfile in $userProfiles) {
    # Search for PCAppStore folders in common locations
    $searchLocations = @(
        "$($userProfile.FullName)\AppData\Local\PCAppStore",
        "$($userProfile.FullName)\AppData\Local\PCAPPSTORE",
        "$($userProfile.FullName)\AppData\Roaming\PCAppStore",
        "$($userProfile.FullName)\AppData\Roaming\PCAPPSTORE",
        "$($userProfile.FullName)\AppData\Local\Programs\PCAppStore",
        "$($userProfile.FullName)\AppData\Local\AUTO APP UPDATER"
    )

    foreach ($location in $searchLocations) {
        if (Test-Path $location) {
            Write-Log "  Found folder: $location" "Yellow"
            try {
                # Take ownership if needed
                cmd /c "takeown /f `"$location`" /r /d y 2>&1" | Out-Null
                cmd /c "icacls `"$location`" /grant administrators:F /t /q 2>&1" | Out-Null

                # Remove the folder
                Remove-Item -Path $location -Recurse -Force -ErrorAction Stop
                $removedItems += "Folder: $location"
                $foldersRemoved++
                Write-Log "  Successfully removed: $location" "Green"
            } catch {
                Write-Log "  Failed to remove $location : $($_.Exception.Message)" "Red"
            }
        }
    }

    # Also search for any folder containing "pcapp" (case insensitive)
    $appDataLocal = "$($userProfile.FullName)\AppData\Local"
    if (Test-Path $appDataLocal) {
        $pcappFolders = Get-ChildItem -Path $appDataLocal -Directory -ErrorAction SilentlyContinue | Where-Object {$_.Name -like "*pcapp*"}
        foreach ($folder in $pcappFolders) {
            Write-Log "  Found matching folder: $($folder.FullName)" "Yellow"
            try {
                # Take ownership if needed
                cmd /c "takeown /f `"$($folder.FullName)`" /r /d y" 2>&1 | Out-Null
                cmd /c "icacls `"$($folder.FullName)`" /grant administrators:F /t /q" 2>&1 | Out-Null

                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                $removedItems += "Folder: $($folder.FullName)"
                $foldersRemoved++
                Write-Log "  Successfully removed: $($folder.FullName)" "Green"
            } catch {
                Write-Log "  Failed to remove $($folder.FullName): $($_.Exception.Message)" "Red"
            }
        }
    }
}

# Check Program Files locations
$programFilesLocations = @(
    "C:\Program Files\PCAppStore",
    "C:\Program Files (x86)\PCAppStore",
    "C:\ProgramData\PCAppStore"
)

foreach ($location in $programFilesLocations) {
    if (Test-Path $location) {
        Write-Log "  Found folder: $location" "Yellow"
        try {
            cmd /c "takeown /f `"$location`" /r /d y" 2>&1 | Out-Null
            cmd /c "icacls `"$location`" /grant administrators:F /t /q" 2>&1 | Out-Null
            Remove-Item -Path $location -Recurse -Force -ErrorAction Stop
            $removedItems += "Folder: $location"
            $foldersRemoved++
            Write-Log "  Successfully removed: $location" "Green"
        } catch {
            Write-Log "  Failed to remove $location : $($_.Exception.Message)" "Red"
        }
    }
}

if ($foldersRemoved -eq 0) {
    Write-Log "  No PCAppStore folders found" "Green"
}

# 3. REMOVE SCHEDULED TASKS
Write-Log "`n[3] Removing Scheduled Tasks..." "Yellow"

$tasksRemoved = 0
$scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.TaskName -like "*pcapp*" -or
    $_.TaskName -like "*PCAppStore*" -or
    $_.Actions.Execute -like "*pcapp*" -or
    $_.Actions.Execute -like "*PCAppStore*"
}

if ($scheduledTasks) {
    foreach ($task in $scheduledTasks) {
        try {
            Write-Log "  Removing task: $($task.TaskName) (Path: $($task.TaskPath))" "Yellow"
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            $removedItems += "Scheduled Task: $($task.TaskPath)$($task.TaskName)"
            $tasksRemoved++
            Write-Log "  Successfully removed task: $($task.TaskName)" "Green"
        } catch {
            Write-Log "  Failed to remove task $($task.TaskName): $($_.Exception.Message)" "Red"
        }
    }
} else {
    Write-Log "  No PCAppStore scheduled tasks found" "Green"
}

# 4. CLEAN REGISTRY KEYS
Write-Log "`n[4] Cleaning Registry Keys..." "Yellow"

$registryKeysRemoved = 0

# Search and remove from HKEY_USERS (all user profiles)
Write-Log "  Scanning HKEY_USERS..." "Gray"
$userHives = Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue

foreach ($hive in $userHives) {
    # Check Software keys
    $softwareKey = "Registry::HKEY_USERS\$($hive.PSChildName)\Software"
    if (Test-Path $softwareKey) {
        $pcappKeys = Get-ChildItem -Path $softwareKey -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSChildName -like "*pcapp*"}
        foreach ($key in $pcappKeys) {
            try {
                Write-Log "  Removing registry key: $($key.PSPath)" "Yellow"
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                $removedItems += "Registry Key: $($key.PSPath)"
                $registryKeysRemoved++
                Write-Log "  Successfully removed: $($key.PSPath)" "Green"
            } catch {
                Write-Log "  Failed to remove $($key.PSPath): $($_.Exception.Message)" "Red"
            }
        }
    }

    # Check Uninstall keys
    $uninstallKey = "Registry::HKEY_USERS\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path $uninstallKey) {
        $pcappUninstall = Get-ChildItem -Path $uninstallKey -ErrorAction SilentlyContinue | Where-Object {
            $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            $props.DisplayName -like "*pcapp*" -or $props.Publisher -like "*pcapp*"
        }
        foreach ($key in $pcappUninstall) {
            try {
                Write-Log "  Removing uninstall key: $($key.PSPath)" "Yellow"
                Remove-Item -Path $key.PSPath -Recurse -Force -ErrorAction Stop
                $removedItems += "Registry Uninstall Key: $($key.PSPath)"
                $registryKeysRemoved++
                Write-Log "  Successfully removed: $($key.PSPath)" "Green"
            } catch {
                Write-Log "  Failed to remove $($key.PSPath): $($_.Exception.Message)" "Red"
            }
        }
    }
}

# Check HKEY_LOCAL_MACHINE
Write-Log "  Scanning HKEY_LOCAL_MACHINE..." "Gray"
$hklmLocations = @(
    "HKLM:\SOFTWARE\PCAppStore",
    "HKLM:\SOFTWARE\WOW6432Node\PCAppStore",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PCAppStore"
)

foreach ($location in $hklmLocations) {
    if (Test-Path $location) {
        try {
            Write-Log "  Removing registry key: $location" "Yellow"
            Remove-Item -Path $location -Recurse -Force -ErrorAction Stop
            $removedItems += "Registry Key: $location"
            $registryKeysRemoved++
            Write-Log "  Successfully removed: $location" "Green"
        } catch {
            Write-Log "  Failed to remove $location : $($_.Exception.Message)" "Red"
        }
    }
}

# Search for any registry values containing "pcapp"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($runKey in $runKeys) {
    if (Test-Path $runKey) {
        $items = Get-ItemProperty $runKey -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | Where-Object {$_.Value -like "*pcapp*"} | ForEach-Object {
                try {
                    Write-Log "  Removing Run key value: $runKey\$($_.Name)" "Yellow"
                    Remove-ItemProperty -Path $runKey -Name $_.Name -ErrorAction Stop
                    $removedItems += "Registry Run Value: $runKey\$($_.Name)"
                    $registryKeysRemoved++
                    Write-Log "  Successfully removed: $($_.Name)" "Green"
                } catch {
                    Write-Log "  Failed to remove $($_.Name): $($_.Exception.Message)" "Red"
                }
            }
        }
    }
}

if ($registryKeysRemoved -eq 0) {
    Write-Log "  No PCAppStore registry keys found" "Green"
}

# 5. CHECK BROWSER EXTENSIONS
Write-Log "`n[5] Checking for Browser Extensions..." "Yellow"
Write-Log "  Manual browser check required:" "Yellow"
Write-Log "  - Chrome: chrome://extensions/" "Gray"
Write-Log "  - Edge: edge://extensions/" "Gray"
Write-Log "  - Firefox: about:addons" "Gray"
Write-Log "  Look for: PCAppStore, PC App Store, or suspicious search extensions" "Gray"

# 6. GENERATE REMOVAL REPORT
Write-Log "`n[6] Generating Removal Report..." "Yellow"

$report = @"
====================================================
PCAPPSTORE ADWARE REMOVAL REPORT
====================================================
Generated: $(Get-Date)
Hostname: $env:COMPUTERNAME
User: $env:USERNAME
Log File: $logFile

SUMMARY:
--------
- Processes Terminated: $killedProcesses
- Folders Removed: $foldersRemoved
- Scheduled Tasks Removed: $tasksRemoved
- Registry Keys Removed: $registryKeysRemoved
- Total Items Removed: $($removedItems.Count)

ITEMS REMOVED:
--------------
"@

foreach ($item in $removedItems) {
    $report += "`n- $item"
}

$report += @"


MANUAL CLEANUP REQUIRED:
------------------------
1. Check browser extensions in Chrome/Edge/Firefox
   - Look for PCAppStore or suspicious search extensions
   - Remove any unwanted search engine redirects

2. Reset browser search settings:
   - Chrome: Settings > Search engine > Manage search engines
   - Edge: Settings > Privacy, search, and services > Address bar and search
   - Firefox: Settings > Search

3. Check browser homepage and new tab settings:
   - Ensure no suspicious URLs are set

4. Run a full antivirus/antimalware scan:
   - Windows Defender or your preferred security software

RECOMMENDATIONS:
----------------
1. Reboot the system to ensure all changes take effect
2. Monitor for any reappearance of PCAppStore
3. Educate users about avoiding freeware bundles
4. Consider implementing application whitelisting
5. Review recent software installations

====================================================
"@

$report | Out-File -FilePath $logFile -Append
Write-Log "`nReport saved to: $logFile" "Cyan"

# Display summary
Write-Host "`n=== REMOVAL COMPLETE ===" -ForegroundColor Green
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Processes Terminated: $killedProcesses" -ForegroundColor White
Write-Host "  Folders Removed: $foldersRemoved" -ForegroundColor White
Write-Host "  Scheduled Tasks Removed: $tasksRemoved" -ForegroundColor White
Write-Host "  Registry Keys Removed: $registryKeysRemoved" -ForegroundColor White
Write-Host "  Total Items: $($removedItems.Count)" -ForegroundColor White
Write-Host "`nLog saved to: $logFile" -ForegroundColor Yellow
Write-Host "`nNEXT STEPS:" -ForegroundColor Cyan
Write-Host "1. REBOOT the system" -ForegroundColor White
Write-Host "2. Check browser extensions manually" -ForegroundColor White
Write-Host "3. Reset browser search settings" -ForegroundColor White
Write-Host "4. Run full antimalware scan" -ForegroundColor White
Write-Host "5. Monitor for reinfection" -ForegroundColor White
Write-Host ""

# Finalize RTR logging - upload to RTR Files and prepare for cleanup
Write-Log "Finalizing log file..." "Cyan"
Complete-RTRLogging -LogFile $logFile -UploadToCloud -RemoveLocal

Write-Host "`n=== RTR LOG UPLOAD READY ===" -ForegroundColor Green
Write-Host "Log will be uploaded to RTR Files for download" -ForegroundColor Gray
