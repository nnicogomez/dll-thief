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

if SafeDllSearchMode is enabled, the search order is as follows:
* The directory from which the application loaded
* The system directory
* The 16-bit system directory
* The Windows directory
* The current directory
* The directories that are listed in the PATH environment variable

If SafeDllSearchMode is disabled, the search order is as follows:
..* The directory from which the application loaded
..* The current directory
..* The system directory
..* The 16-bit system directory
..* The Windows directory
..* The directories that are listed in the PATH environment variable

Knowing that, i created dll-thief. dll-thief wants to be an automatization of the DLL hijacking process. Using DLL hijacking we will be able to analyze the processes behaviour in a little time, learning what DLLs are used by what process and if these DLLs are found or not. When the script detects that a DLL was not found, it will treat to write a malicious DLL in the paths (mentioned above). 

## Installation
1. Clone repo
`git clone https://github.com/nnicogomez/dll-thief.git`
2. Install requirements
`pip install -r requirements.txt`

## Usage
`.\dll-thief TARGET_PROCESS MALICIOUS_DLL`

## To do - In process
.** Module to put the DLL in the "vulnerable" path
.** Improve the process of user write access validation
.** Database with know vulnerable $PATH entries

# Copyright
dll-thief.ps1 - A linux tool to perform password spraying attacks.

Nicolás Gómez - Copyright © 2020

Those programs are free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Those programs are distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/.

#References:
https://stackoverflow.com/questions/518228/is-it-possible-to-add-a-directory-to-dll-search-path-from-a-batch-file-or-cmd-sc
https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN#standard_search_order_for_desktop_applications
https://itm4n.github.io/windows-server-netman-dll-hijacking/
https://pentestlab.blog/2020/03/04/persistence-dll-hijacking/
