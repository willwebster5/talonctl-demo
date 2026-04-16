#This script will fully remove PUP Onelaunch from users devices.

# Check if Chromium.exe is running from the OneLaunch path. If so, kill it.
$OneLaunchProcess = get-process chromium -ErrorAction SilentlyContinue | where {$_.path -like "C:\Users\*\AppData\Local\OneLaunch\*\chromium\chromium.exe"}
if ($OneLaunchProcess) {
    $OneLaunchProcess | foreach {
        Stop-Process $_ -Force -Confirm:$false
        Write-Output "Terminated OneLaunch Chromium process: $($_.Id)"
    }
}

# Check if OneLaunch.exe is running. If so, kill it.
$OneLaunchProcess2 = get-process onelaunch -ErrorAction SilentlyContinue | where {$_.path -like "C:\Users\*\AppData\Local\OneLaunch\*\onelaunch.exe"}
if ($OneLaunchProcess2) {
    $OneLaunchProcess2 | foreach {
        Stop-Process $_ -Force -Confirm:$false
        Write-Output "Terminated OneLaunch process: $($_.Id)"
    }
}

# Check if OneLaunchTray.exe is running. If so, kill it.
$OneLaunchProcess3 = get-process onelaunchtray -ErrorAction SilentlyContinue | where {$_.path -like "C:\Users\*\AppData\Local\OneLaunch\*\onelaunchtray.exe"}
if ($OneLaunchProcess3) {
    $OneLaunchProcess3 | foreach {
        Stop-Process $_ -Force -Confirm:$false
        Write-Output "Terminated OneLaunchTray process: $($_.Id)"
    }
}

# Check if "OneLaunch" bin or start menu folders exist under any user profile.
$Profiles = Get-ChildItem C:\Users
foreach ($Profile in $Profiles) {
    # Search user profiles for the OneLaunch bin dir.
    $OneLaunchFolder = Get-ChildItem OneLaunch -path "$($Profile.Fullname)\appdata\local" -ErrorAction SilentlyContinue
    # If bin dir exists, delete it.
    If ($OneLaunchFolder) {
        $OneLaunchFolder.fullname | foreach {
            Remove-Item $_ -Force -Recurse -Confirm:$False
            Write-Output "Deleted OneLaunch folder: $_"
        }
    }

    # Search user profiles for the OneLaunch start menu folder.
    $StartMenuFolder = Get-ChildItem OneLaunch -path "$($Profile.Fullname)\appdata\roaming\microsoft\windows\start menu\programs" -ErrorAction SilentlyContinue
    # If the start menu dir exists, delete it.
    If ($StartMenuFolder) {
        $StartMenuFolder.fullname | foreach {
            Remove-Item $_ -Force -Recurse -Confirm:$False
            Write-Output "Deleted OneLaunch Start Menu folder: $_"
        }
    }
}

# Get any scheduled tasks "OneLaunchLaunchTask" and unregister them.
Get-ScheduledTask -TaskName OneLaunchLaunchTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
Write-Output "Unregistered OneLaunch scheduled tasks."

# Identify and remove any installation keys in HKEY_USERS
$RegKeys = Get-childitem "registry::\HKEY_USERS" -ErrorAction SilentlyContinue | foreach {
    get-childitem -path "Registry::\HKEY_USERS\$($_.pschildname)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ErrorAction SilentlyContinue
}
# Limit installation keys resultset to OneLaunch
$UninstallKeys = $RegKeys | where {$_.pschildname -eq '{4947c51a-26a9-4ed0-9a7b-c21e5ae0e71a}_is1'}
# Remove any installation keys for OneLaunch, if any exist.
if ($UninstallKeys) {
    $UninstallKeys | foreach {
        Remove-Item "$($_.PSPath)" -Force -Recurse -Confirm:$False
        Write-Output "Removed OneLaunch install Registry Key: $($_.PSPath)"
    }
}

# Find and delete any reg keys in HKEY_USERS\[SID]\Software\ for OneLaunch
foreach ($User in (Get-ChildItem "registry::\hkey_users")) {
    $SoftwareKeys = Get-ChildItem "$($User.pspath)\software\OneLaunch" -ErrorAction SilentlyContinue
    # If any keys exist, recursively delete them.
    if ($SoftwareKeys) {
        $SoftwareKeys | foreach {
            Remove-Item "$($_.PSPath)" -Force -Recurse -Confirm:$False
            Write-Output "Deleted OneLaunch Software Registry Key: $($_.PSPath)"
        }
    }
}

Write-Output "OneLaunch removal process completed."
