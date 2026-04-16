$currentUser = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName

if ($null -ne $currentUser) {
    $userDomain = $currentUser.Split('\')[0]
    $userName = $currentUser.Split('\')[1]

    Write-Output "Current user: $userDomain\$userName"
} else {
    Write-Output "No user currently logged in"
}
