function Get-BrowserData {
    <#
    .SYNOPSIS
      Dumps Browser Information
      Original Author: u/424f424f
      Modified by: 51Ev34S
      License: BSD 3-Clause
      Required Dependencies: None
      Optional Dependencies: None
    .DESCRIPTION
      Enumerates browser history or bookmarks for a Chrome, Edge (Chromium) Internet Explorer,
      and/or Firefox browsers on Windows machines.
    .PARAMETER Browser
      The type of browser to enumerate, 'Chrome', 'Edge', 'IE', 'Firefox' or 'All'
    .PARAMETER Datatype
      Type of data to enumerate, 'History' or 'Bookmarks'
    .PARAMETER UserName
      Specific username to search browser information for.
    .PARAMETER Search
      Term to search for
    .EXAMPLE
      PS C:\> Get-BrowserData
      Enumerates browser information for all supported browsers for all current users.
    .EXAMPLE
      PS C:\> Get-BrowserData -Browser IE -Datatype Bookmarks -UserName user1
      Enumerates bookmarks for Internet Explorer for the user 'user1'.
    .EXAMPLE
      PS C:\> Get-BrowserData -Browser All -Datatype History -UserName user1 -Search 'github'
      Enumerates bookmarks for Internet Explorer for the user 'user1' and only returns
      results matching the search term 'github'.
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0)]
        [String[]]
        [ValidateSet('Chrome', 'EdgeChromium', 'IE', 'FireFox', 'All')]
        $Browser = 'All',
        [Parameter(Position = 1)]
        [String[]]
        [ValidateSet('History', 'Bookmarks', 'All')]
        $DataType = 'All',
        [Parameter(Position = 2)]
        [String]
        $UserName = '',
        [Parameter(Position = 3)]
        [String]
        $Search = ''
    )

    function ConvertFrom-Json20([object] $item) {
        # Fix: Increase maxJsonLength to handle larger JSON files
        Add-Type -AssemblyName System.Web.Extensions
        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        # Set a higher maximum length (100MB)
        $ps_js.MaxJsonLength = 104857600
        return , $ps_js.DeserializeObject($item)
    }

    function Get-ChromeHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find Chrome History for username: $UserName"
        }
        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History" | Select-String -AllMatches $regex | ForEach-Object { ($_.Matches).Value } | Sort-Object -Unique
        $Value | ForEach-Object {
            $Key = $_
            if ($Key -match $Search) {
                New-Object -TypeName PSObject -Property @{
                    User     = $UserName
                    Browser  = 'Chrome'
                    DataType = 'History'
                    Data     = $_
                }
            }
        }
    }
    
    function Get-ChromeBookmarks {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find Chrome Bookmarks for username: $UserName"
        }
        else {
            try {
                $Json = Get-Content $Path
                $Output = ConvertFrom-Json20($Json)
                $Jsonobject = $Output.roots.bookmark_bar.children
                $Jsonobject.url | Sort-Object -Unique | ForEach-Object {
                    if ($_ -match $Search) {
                        New-Object -TypeName PSObject -Property @{
                            User     = $UserName
                            Browser  = 'Chrome'
                            DataType = 'Bookmark'
                            Data     = $_
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error processing Chrome bookmarks: $_"
            }
        }
    }
    
    function Get-EdgeChromiumHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\History"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find Edge History for username: $UserName"
        }
        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
        $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\History" | Select-String -AllMatches $regex | ForEach-Object { ($_.Matches).Value } | Sort-Object -Unique
        $Value | ForEach-Object {
            $Key = $_
            if ($Key -match $Search) {
                New-Object -TypeName PSObject -Property @{
                    User     = $UserName
                    Browser  = 'Edge(Chromium)'
                    DataType = 'History'
                    Data     = $_
                }
            }
        }
    }
    
    function Get-EdgeChromiumBookmarks {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find Edge Bookmarks for username: $UserName"
        }
        else {
            try {
                $Json = Get-Content $Path
                $Output = ConvertFrom-Json20($Json)
                $Jsonobject = $Output.roots.bookmark_bar.children
                $Jsonobject.url | Sort-Object -Unique | ForEach-Object {
                    if ($_ -match $Search) {
                        New-Object -TypeName PSObject -Property @{
                            User     = $UserName
                            Browser  = 'Edge(Chromium)'
                            DataType = 'Bookmark'
                            Data     = $_
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error processing Edge bookmarks: $_"
            }
        }
    }
    
    function Get-InternetExplorerHistory {
        #https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/
        $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
        
        ForEach ($Path in $Paths) {
            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
            $Path = $Path | Select-Object -ExpandProperty PSPath
            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
            if (-not (Test-Path -Path $UserPath)) {
                Write-Verbose "[!] Could not find IE History for SID: $Path"
            }
            else {
                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Key = $_
                    $Key.GetValueNames() | ForEach-Object {
                        $Value = $Key.GetValue($_)
                        if ($Value -match $Search) {
                            New-Object -TypeName PSObject -Property @{
                                User     = $UserName
                                Browser  = 'IE'
                                DataType = 'History'
                                Data     = $Value
                            }
                        }
                    }
                }
            }
        }
    }
   
    function Get-InternetExplorerBookmarks {
        $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
        ForEach ($URL in $URLs) {
            if ($URL.FullName -match 'Favorites') {
                $User = $URL.FullName.split('\')[2]
                Get-Content -Path $URL.FullName | ForEach-Object {
                    try {
                        if ($_.StartsWith('URL')) {
                            # parse the .url body to extract the actual bookmark location
                            $URL = $_.Substring($_.IndexOf('=') + 1)
                            
                            if ($URL -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User     = $User
                                    Browser  = 'IE'
                                    DataType = 'Bookmark'
                                    Data     = $URL
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error parsing url: $_"
                    }
                }
            }
        }
    }

    function Get-FireFoxBookmarks {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find FireFox Profiles for username: $UserName"
        }
        else {
            # Firefox profiles can have different naming patterns
            $Profiles = Get-ChildItem -Path "$Path" -Directory -ErrorAction SilentlyContinue
            
            foreach ($ProfileDir in $Profiles) {
                try {
                    # Firefox stores bookmarks in places.sqlite or in a JSON backup
                    $JsonBackup = Join-Path $ProfileDir.FullName "bookmarkbackups"
                    
                    if (Test-Path $JsonBackup) {
                        # Get the most recent JSON backup file
                        $BackupFiles = Get-ChildItem -Path $JsonBackup -Filter "*.jsonlz4" -ErrorAction SilentlyContinue | 
                                       Sort-Object LastWriteTime -Descending
                        
                        if ($BackupFiles.Count -gt 0) {
                            Write-Verbose "Found Firefox bookmark backups in $($ProfileDir.Name)"
                            
                            # Firefox bookmark JSON files need special processing
                            # For this version, we'll parse the places.sqlite file as a workaround
                            $PlacesFile = Join-Path $ProfileDir.FullName "places.sqlite"
                            
                            if (Test-Path $PlacesFile) {
                                # Extract bookmark URLs with regex
                                $FileContent = [System.IO.File]::ReadAllBytes($PlacesFile)
                                $FileText = [System.Text.Encoding]::ASCII.GetString($FileContent)
                                
                                $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
                                $Matches = [regex]::Matches($FileText, $Regex)
                                
                                # We can't easily distinguish between history and bookmarks in this approach
                                # So we'll mark some as potential bookmarks based on frequency and position
                                $UrlCounts = @{}
                                
                                $Matches | ForEach-Object {
                                    $Url = $_.Value
                                    if ($UrlCounts.ContainsKey($Url)) {
                                        $UrlCounts[$Url]++
                                    } else {
                                        $UrlCounts[$Url] = 1
                                    }
                                }
                                
                                # URLs that appear more frequently could be bookmarks
                                $UrlCounts.GetEnumerator() | Where-Object { $_.Value -gt 1 } | ForEach-Object {
                                    $Url = $_.Key
                                    if ($Url -match $Search) {
                                        New-Object -TypeName PSObject -Property @{
                                            User     = $UserName
                                            Browser  = 'Firefox'
                                            DataType = 'Bookmark'
                                            Data     = $Url
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error processing Firefox bookmarks for profile $($ProfileDir.Name): $_"
                }
            }
        }
    }

    function Get-FireFoxHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[!] Could not find FireFox History for username: $UserName"
        }
        else {
            # Firefox profiles can have different naming patterns
            $Profiles = Get-ChildItem -Path "$Path" -Directory -ErrorAction SilentlyContinue
            
            foreach ($ProfileDir in $Profiles) {
                try {
                    # The places.sqlite file contains Firefox history
                    $PlacesFile = Join-Path $ProfileDir.FullName "places.sqlite"
                    
                    if (Test-Path $PlacesFile) {
                        Write-Verbose "Analyzing Firefox profile: $($ProfileDir.Name)"
                        
                        # Note: SQLite files can't be read directly with Get-Content
                        # We'll extract URLs using regex from the binary content
                        $FileContent = [System.IO.File]::ReadAllBytes($PlacesFile)
                        $FileText = [System.Text.Encoding]::ASCII.GetString($FileContent)
                        
                        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
                        $Matches = [regex]::Matches($FileText, $Regex)
                        
                        $Matches | ForEach-Object {
                            $Url = $_.Value
                            if ($Url -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User     = $UserName
                                    Browser  = 'Firefox'
                                    DataType = 'History'
                                    Data     = $Url
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error processing Firefox profile $($ProfileDir.Name): $_"
                }
            }
        }
    }

    if (!$UserName) {
        $UserName = "$ENV:USERNAME"
    }
    if (($Browser -Contains 'All') -or ($Browser -Contains 'Chrome')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-ChromeHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-ChromeBookmarks
        }
    }
    if (($Browser -Contains 'All') -or ($Browser -Contains 'EdgeChromium')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-EdgeChromiumHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-EdgeChromiumBookmarks
        }
    }
    if (($Browser -Contains 'All') -or ($Browser -Contains 'IE')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-InternetExplorerHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-InternetExplorerBookmarks
        }
    }
    if (($Browser -Contains 'All') -or ($Browser -Contains 'FireFox')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-FireFoxHistory
        }
        # Now let's add Firefox bookmarks function
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-FireFoxBookmarks
        }
    }
}

# Main execution
(Get-ChildItem "c:\Users" | Sort-Object LastWriteTime -Descending | Select-Object Name -first 1).Name | ForEach-Object {
    Write-Host "Checking: $_"
    Get-BrowserData -UserName $_ -ErrorAction SilentlyContinue
}