#This script will remove all persistence of Wave Browser from a users computer, including registry keys, scheduled tasks, and other installers.

$ErrorActionPreference = 'SilentlyContinue'

$badprocs=get-process | ?{$_.name -like 'Wave*Browser*'} | select -exp Id;

echo '------------------------';

echo 'Process(es) Terminated'

echo '------------------------';

if ($badprocs){

Foreach ($badproc in $badprocs){

echo $badproc

stop-process -Id $badproc -force

}

}

else {

echo 'No Processes Terminated.'

}

$stasks = schtasks /query /fo csv /v | convertfrom-csv | ?{$_.TaskName -like 'Wavesor*'} | select -exp TaskName

echo ''

echo '----------------------------';

' Scheduled Task(s) Removed:'

echo '----------------------------';

if ($stasks){

Foreach ($task in $stasks){

echo "$task"

schtasks /delete /tn $task /F

}

}

else {"No Scheduled Tasks Found."};

$badDirs = 'C:\Users\*\Wavesor Software',

'C:\Users\*\Downloads\Wave Browser*.exe',

'C:\Users\*\AppData\Local\WaveBrowser',

'C:\Windows\System32\Tasks\Wavesor Software_*',

'C:\WINDOWS\SYSTEM32\TASKS\WAVESORSWUPDATERTASKUSER*CORE',

'C:\WINDOWS\SYSTEM32\TASKS\WAVESORSWUPDATERTASKUSER*UA',

'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\WINDOWS\START MENU\PROGRAMS\WAVEBROWSER.LNK',

'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\WAVEBROWSER.LNK',

'C:\USERS\*\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\USER PINNED\TASKBAR\WAVEBROWSER.LNK'

echo ''

echo '-------------------------------';

echo 'File System Artifacts Removed;'

echo '-------------------------------';

start-sleep -s 2;

ForEach ($badDir in $badDirs) {

$dsfolder = gi -Path $badDir -ea 0| select -exp fullname;

if ( $dsfolder) {

echo "$dsfolder"

rm $dsfolder -recurse -force -ea 0

}

else {

}

}

$checkhandle = gi -Path 'C:\Users\*\AppData\Local\WaveBrowser' -ea 0| select -exp fullname;

if ($checkhandle){

echo ""

echo "NOTE: C:\Users\*\AppData\Local\WaveBrowser' STILL EXISTS! A PROCESS HAS AN OPEN HANDLE TO IT!"

}

$badreg=

'Registry::HKU\*\Software\WaveBrowser',

'Registry::HKU\*\SOFTWARE\CLIENTS\STARTMENUINTERNET\WaveBrowser.*',

'Registry::HKU\*\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\APP PATHS\wavebrowser.exe',

'Registry::HKU\*\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\WaveBrowser',

'Registry::HKU\*\Software\Wavesor',

'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\WavesorSWUpdaterTaskUser*UA',

'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\WavesorSWUpdaterTaskUser*Core',

'Registry::HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TREE\Wavesor Software_*'

echo ''

echo '---------------------------';

echo 'Registry Artifacts Removed:'

echo '---------------------------';

Foreach ($reg in $badreg){

$regoutput= gi -path $reg | select -exp Name

if ($regoutput){

"$regoutput `n"

reg delete $regoutput /f

}

else {}

}

$badreg2=

'Registry::HKU\*\Software\Microsoft\Windows\CurrentVersion\Run',

'Registry::HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'

echo ''

echo '----------------------------------';

echo 'Registry Run Persistence Removed:'

echo '----------------------------------';

Foreach ($reg2 in $badreg2){

$regoutput= gi -path $reg2 -ea silentlycontinue | ? {$_.Property -like 'Wavesor SWUpdater'} | select -exp Property ;

$regpath = gi -path $reg2 -ea silentlycontinue | ? {$_.Property -like 'Wavesor SWUpdater'} | select -exp Name ;

Foreach($prop in $regoutput){

If ($prop -like 'Wavesor SWUpdater'){

"$regpath value: $prop `n"

reg delete $regpath /v $prop /f

}

else {}

}

}