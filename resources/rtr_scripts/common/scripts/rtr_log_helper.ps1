# RTR Log Helper Functions
# Include this in RTR scripts to handle log management
# Usage: . $PSScriptRoot\..\common\RTR-LogHelper.ps1

<#
.SYNOPSIS
Helper functions for RTR scripts to manage logs through RTR Files.

.DESCRIPTION
This module provides reusable functions for RTR scripts to:
- Create standardized log file names
- Upload logs to RTR Files repository using 'put' command
- Clean up local log files
- Provide consistent logging patterns

.NOTES
These functions are designed to be dot-sourced into RTR scripts.
They work within the RTR environment on target endpoints.
#>

function Get-RTRLogFileName {
    <#
    .SYNOPSIS
    Generate a standardized RTR log file name.

    .PARAMETER ScriptName
    Name of the script creating the log (e.g., "PCAppStore_Removal")

    .PARAMETER Extension
    File extension (default: ".log")

    .EXAMPLE
    $logFile = Get-RTRLogFileName -ScriptName "PCAppStore_Removal"
    # Returns: C:\PCAppStore_Removal_HOSTNAME_20251024_134501.log
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,

        [Parameter(Mandatory=$false)]
        [string]$BasePath = "C:\",

        [Parameter(Mandatory=$false)]
        [string]$Extension = ".log"
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $hostname = $env:COMPUTERNAME
    $fileName = "${ScriptName}_${hostname}_${timestamp}${Extension}"

    return Join-Path $BasePath $fileName
}

function Write-RTRLog {
    <#
    .SYNOPSIS
    Write a log entry with timestamp to the RTR log file.

    .PARAMETER Message
    Message to log

    .PARAMETER LogFile
    Path to the log file

    .PARAMETER Level
    Log level: INFO, WARNING, ERROR, SUCCESS

    .EXAMPLE
    Write-RTRLog -Message "Starting remediation" -LogFile $logFile -Level "INFO"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [string]$LogFile,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    Add-Content -Path $LogFile -Value $logEntry
}

function Send-RTRLogToCloud {
    <#
    .SYNOPSIS
    Upload log file to RTR Files repository using the 'put' command.

    .DESCRIPTION
    This function is designed to be called from within an RTR session.
    It outputs the command that RTR should execute to upload the file.

    .PARAMETER LogPath
    Full path to the log file on the endpoint

    .EXAMPLE
    Send-RTRLogToCloud -LogPath "C:\PCAppStore_Removal_20251024_134501.log"

    .NOTES
    This function outputs instructions for the RTR script.
    The actual upload is handled by outputting a marker that PSFalcon can detect.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath
    )

    if (Test-Path $LogPath) {
        $fileName = Split-Path $LogPath -Leaf

        # Output marker for PSFalcon to detect
        Write-Output "RTR_LOG_UPLOAD_REQUIRED: $LogPath"
        Write-Output "RTR_LOG_FILE_NAME: $fileName"

        return $true
    } else {
        Write-Warning "Log file not found: $LogPath"
        return $false
    }
}

function Remove-LocalRTRLog {
    <#
    .SYNOPSIS
    Clean up local log file after upload to RTR Files.

    .PARAMETER LogPath
    Full path to the log file to remove

    .PARAMETER Force
    Force deletion without confirmation

    .EXAMPLE
    Remove-LocalRTRLog -LogPath "C:\PCAppStore_Removal_20251024_134501.log" -Force
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    if (Test-Path $LogPath) {
        try {
            Remove-Item -Path $LogPath -Force:$Force -ErrorAction Stop
            Write-Output "RTR_LOG_CLEANUP: Removed local log: $LogPath"
            return $true
        } catch {
            Write-Warning "Failed to remove local log: $LogPath - $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Verbose "Log file does not exist: $LogPath"
        return $false
    }
}

function Initialize-RTRLogging {
    <#
    .SYNOPSIS
    Initialize RTR logging for a script.

    .DESCRIPTION
    Creates a log file and returns the path. Sets up the logging environment.

    .PARAMETER ScriptName
    Name of the script (e.g., "PCAppStore_Removal")

    .PARAMETER BasePath
    Base directory for logs (default: C:\)

    .EXAMPLE
    $logFile = Initialize-RTRLogging -ScriptName "PCAppStore_Removal"
    Write-RTRLog -Message "Script started" -LogFile $logFile

    .OUTPUTS
    Returns the full path to the created log file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,

        [Parameter(Mandatory=$false)]
        [string]$BasePath = "C:\"
    )

    $logFile = Get-RTRLogFileName -ScriptName $ScriptName -BasePath $BasePath

    # Create log file with header
    $header = @"
================================================================================
RTR Script Log: $ScriptName
Hostname: $env:COMPUTERNAME
User: $env:USERNAME
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================

"@

    Set-Content -Path $logFile -Value $header

    Write-Output "RTR_LOG_INITIALIZED: $logFile"

    return $logFile
}

function Complete-RTRLogging {
    <#
    .SYNOPSIS
    Finalize RTR logging and prepare for upload.

    .DESCRIPTION
    Adds footer to log file, marks it for upload, and optionally removes local copy.

    .PARAMETER LogFile
    Path to the log file

    .PARAMETER UploadToCloud
    Upload the log to RTR Files

    .PARAMETER RemoveLocal
    Remove local log file after marking for upload

    .EXAMPLE
    Complete-RTRLogging -LogFile $logFile -UploadToCloud -RemoveLocal
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogFile,

        [Parameter(Mandatory=$false)]
        [switch]$UploadToCloud,

        [Parameter(Mandatory=$false)]
        [switch]$RemoveLocal
    )

    # Add footer
    $footer = @"

================================================================================
Script Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
================================================================================
"@

    Add-Content -Path $LogFile -Value $footer

    if ($UploadToCloud) {
        Send-RTRLogToCloud -LogPath $LogFile
    }

    if ($RemoveLocal) {
        # Note: Actual removal happens after upload is confirmed by PSFalcon
        Write-Output "RTR_LOG_REMOVE_AFTER_UPLOAD: $LogFile"
    }

    return $true
}

# Export functions (only when loaded as a module, not when run as a standalone script)
if ($MyInvocation.MyCommand.ScriptBlock.Module) {
    Export-ModuleMember -Function @(
        'Get-RTRLogFileName',
        'Write-RTRLog',
        'Send-RTRLogToCloud',
        'Remove-LocalRTRLog',
        'Initialize-RTRLogging',
        'Complete-RTRLogging'
    )
}

# When run standalone via RTR, write this script to a known location on the
# endpoint so subsequent scripts can dot-source the functions.
$deployPath = "C:\CrowdStrike\RTR-LogHelper.ps1"
if (-not (Test-Path "C:\CrowdStrike")) {
    New-Item -Path "C:\CrowdStrike" -ItemType Directory -Force | Out-Null
}
# Write the function definitions to the deploy path
$scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
Set-Content -Path $deployPath -Value $scriptContent -Force
Write-Output "RTR_LOG_HELPER_DEPLOYED: $deployPath"
