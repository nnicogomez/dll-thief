<#
.Synopsis
   This script treat to detects all the paths where DLL injection could be possible.
.DESCRIPTION
   This script use only powershell tools to find the dll used by the target process. Once sososo
.EXAMPLE
   ./Set-DatabaseOwnerToSA.ps1 <process>
.EXAMPLE
   ./Set-DatabaseOwnerToSA.ps1 firefox
.EXAMPLE
   ./Set-DatabaseOwnerToSA.ps1 explorer
#>

$process=$args[0] #process
function Write-HostCenter { param($Message) Write-Host ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($Message.Length / 2)))), $Message) }
Write-HostCenter "**************DLL's CANDIDATES SELECTION SECTION**************"
$tmp = ".\$process.tmp"
$final = ".\$process-dll-list.prc"
$statusf = ".\$process-dll-status.prc"
Get-Process $process | select -ExpandProperty modules | Format-Table -AutoSize -Property FileName | Out-File -FilePath $tmp -Append
Get-Content $tmp | Where-Object {$_ -notmatch 'FileName|----'} | ? {$_.trim() -ne "" } | Set-Content $final
Remove-Item $tmp

$content = Get-Content $final
$content | Foreach {$_.TrimEnd()} | Set-Content $final

$not_found = [System.Collections.ArrayList]@()
$files_only = [System.Collections.ArrayList]@()
$i=0
foreach($fl in Get-Content $final) {
    #Write-Host ("Testing $fl")
    if (Test-Path $fl -PathType leaf){
    echo "$fl,FILE EXISTS" | Out-File -FilePath $statusf -Append
    }
	else{ 
    $not_found.add($fl) | out-null
    $files_only.add($fl.Split('\')[-1]) | out-null
    echo "$fl,FILE NOT FOUND" | Out-File -FilePath $statusf -Append
	echo "CANDIDATE: $fl - FILE NOT FOUND"
    $i++
	}
}
<#
foreach($fl in $not_found) {
    Write-Host "$fl"
}

foreach($fl in $files_only) {
    Write-Host "$fl"
}
 #>

Write-HostCenter "**************SEARCH SECTION**************"
Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN CURRENT DIRECTORY" | Out-File -FilePath $statusf -Append

$not_found = [System.Collections.ArrayList]@()
Get-Process $process | Select-Object Path | Out-File -FilePath tmp.io -Append
Get-Content tmp.io | Where-Object {$_ -notmatch 'Path|----'} | ? {$_.trim() -ne "" } | Set-Content tmp1.io 
rm tmp.io
$endp = cat "tmp1.io"
$endp = $endp.Substring(0, $endp.lastIndexOf('\'))
rm tmp1.io
$bnd=0
foreach($file in $files_only) {
    Write-Host "Current file: $file"
    Write-Host "Current path: $endp"
    if (Test-Path "$endp$file" -PathType leaf){
        Write-Host "Current file: $endp\$file"
            Write-Host "$file,FILE EXISTS,$endp" | Out-File -FilePath $statusf -Append
            $bnd=1
        }
    }
    $paths= "$endp\"
    if ($bnd -eq 0){
        Write-Host "CANDIDATE: $file not exists in $endp" | Out-File -FilePath $statusf -Append
        #Write-Host "Testing write access"
        $cu = whoami
        $current_user = $cu.Split('\')[-1]
            #Write-Host "Current path: $paths"
            if (Test-Path $paths){
                $permission = (Get-Acl $paths).Access | ?{$_.IdentityReference -match $current_user} | Select IdentityReference,FileSystemRights
                If ($permission){
                    $permission | % {Write-Host -BackgroundColor Red  "***************** User $cu has '$($_.FileSystemRights)' rights on folder $paths"}
                }
                Else {
                    Write-Host "User $cu doesn't have any permission on $paths"
                }
            }
        }

Write-Host -BackgroundColor Black "------------------------------> SEARCHING IN PATH ENTRIES" | Out-File -FilePath $statusf -Append
$windows_path = $env:Path
$paths_windows = $windows_path -split ';'
$paths_windows

$not_found = [System.Collections.ArrayList]@()
$candidates_paths = [System.Collections.ArrayList]@()
$i=0
foreach($endp in $paths_windows) {
    #Write-Host "Current path: $endp"
    $bnd=0
    foreach($file in $files_only) {
        #Write-Host "Current file: $file"
        if (Test-Path "$endp$file" -PathType leaf){
            Write-Host "$file,FILE EXISTS,$endp" | Out-File -FilePath $statusf -Append
            $bnd=1
        }
    }
    if ($bnd -eq 0){
        Write-Host "CANDIDATE: $file not exists in $endp" | Out-File -FilePath $statusf -Append
        $candidates_paths.add($endp) | out-null
    }
}
Write-Host "Testing write access"
$cu = whoami
$current_user = $cu.Split('\')[-1]  
foreach($paths in $candidates_paths) {
    #Write-Host "Current path: $paths"
    if (Test-Path $paths){
        $permission = (Get-Acl $paths).Access | ?{$_.IdentityReference -match $current_user} | Select IdentityReference,FileSystemRights
        If ($permission){
        $permission | % {Write-Host -BackgroundColor Red "***************** User $cu has '$($_.FileSystemRights)' rights on folder $paths"}
        }
        Else {
        Write-Host "User $cu doesn't have any permission on $paths"
        }
    }
}


<#Write-Host "Testeando si se puede escribir"
fsutil file createnew testdll.dll 760
$Folder = "D:\share"
foreach ($letter in $letterArray)
{
  Write-Host $letter
}
Directorio en el que se encuentra instalada la aplicación
	Directorio de sistema (C:\Windows\System32\)
	Directorio de sistema de 16bits (C:\Windows\System\)
	Directorio de Windows (C:\Windows\)
	Directorio actual desde el cual estoy trabajando
	Directorios listados en la variable %PATH% del sistema.
    Write-Host "Searching in C:\Windows\System32\"

Write-Host "Searching in C:\Windows\System\"

Write-Host "Searching in C:\Windows\"

Write-Host "Searching in DIRECTORIO_DE_PROCESO"


#>