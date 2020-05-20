# gran-theft-dll

## Synopsys and objetive
DLL hijacking is techique which allows to abuse the library search order to gain execution in a process. If the current user is able to write in the directories where the system search, it will be possible to put a malicious DLL on site. When the executable attempts to load the expected library, they will instead load the malicious one. 

Commonly, Windows treat to obtain the DLLs in the standard indicated location, but if the DLL is not found there, OS will find these in some known directories:

* The directory from which the application loaded
* The system directory
* The 16-bit system directory
* The Windows directory
* The current directory
* The directories that are listed in the PATH environment variable

The search order depends of `SafeDllSearchMode`.
For more information about SafeDllSearchMode, see https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

if `SafeDllSearchMode` is enabled, the search order is as follows:
* The directory from which the application loaded
* The system directory
* The 16-bit system directory
* The Windows directory
* The current directory
* The directories that are listed in the PATH environment variable

If `SafeDllSearchMode is` disabled, the search order is as follows:
* The directory from which the application loaded
* The current directory
* The system directory
* The 16-bit system directory
* The Windows directory
* The directories that are listed in the PATH environment variable

Knowing that, it was created `grand theft dll` (gtdll in advance). Application wants to be an automatization of the DLL hijacking process. Using gtdll for DLL hijacking attacks we will be able to analyze the processes behaviour in a little time, learning what DLLs are used by what process and if these DLLs are found or not. When the script detects that a DLL was not found, it will treat to write a malicious DLL in the paths (mentioned above). 

## Main features
* Search missing dlls in standard directory
* Search missing dlls in windows search directories
* Test user access to aforementioned directories
* Write the malicious dll in "vulnerable" directories

## Installation
1. Clone repo:
`git clone https://github.com/nnicogomez/grand-theft-dll.git`
2. Install requirements:
`pip install -r requirements.txt`

## Parameters
`-process <process>: Mandatory parameter. Indicates the target process. This process should be active at the moment of execute the script. Don't include ".exe" extention.  

-autoexploitation: Switch parameter. If it is activated, script will try to perform the dll hijacking.  

-type <autoxplotation_mode>:  

  f: First path mode. The script will inject the dll file in the first possible path.  
  
  a: Annihilation mode. The script will inject the dll in all the paths.  
  
-dllp <dll_path>: Malicious dll path.  

-url <dll_url>: Download the dll from internet. `
## Help
`Get-Help .\gtdll.ps1`

## Typical usage
`.\gtdll.ps1 -process explorer`

## To do - In process
* Database with know vulnerable $PATH entries
* ...

# Copyright
grand-theft.dll - A Windows tool to perform DLL hijacking attacks.

Nicolás Gómez - Copyright © 2020

Those programs are free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Those programs are distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.

# References:
* https://stackoverflow.com/questions/518228/is-it-possible-to-add-a-directory-to-dll-search-path-from-a-batch-file-or-cmd-sc
* https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN#standard_search_order_for_desktop_applications
* https://itm4n.github.io/windows-server-netman-dll-hijacking/
* https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
* https://ired.team/offensive-security/privilege-escalation/t1038-dll-hijacking
* https://www.oreilly.com/library/view/windows-server-cookbook/0596006330/ch06s10.html
* https://www.sysadmit.com/2019/07/windows-saber-dll-utiliza-programa.htm
