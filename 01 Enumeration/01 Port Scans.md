Quick nmap scan:
```
nmap -F ip
```

most efficient with no loss of quality scan:
```
sudo nmap -Pn -n 10.129.157.180 -sCV -p- --open -vvv
```

if notice different ports between `-F` and quality scan:
```
nmap -p- --min-rate 10000 10.129.249.105 -vvv
```
then list each port:
```
nmap -p 22,25,80,110,119,4555 -sCV 10.10.10.51 -vvv
```
- can use `:%s/\/.*$// | %s/\n\(\d\)/,\1/g` in vim to leave only the ports from previous nmap scan and reshape with commas ie 1,2,3,4

if IP redirects to http site, rescan with redirect name
```
sudo nmap -p 22,80 -sCV precious.htb -vvv
```
- might find other things such as .git repositories, etc

quick UDP scan
```
sudo nmap -sU --top-ports 10 10.129.224.93
```
- can also run snmp port scan for more info
```
sudo nmap -sU -p161 -sCV 10.129.228.102 -vvv --open -Pn
```

~extra~

also can try rustscan:
```
rustscan -a 192.168.x.x --ulimit 5000 -- -sCV
```


For MS02 or DC01 via Ligolo:
```
nmap -sCV -p- 192.168.1.2,192.168.1.1
```
or
```
rustscan -a 10.10.138.152,10.10.138.154 --ulimit 5000 -- -Pn -sCV
```


Interesting options:
`-sC` default scripts
`-sV` version on port
`-sV --version-all` higher possibility of correctness; slower
`-T4`faster, but less reliable

Useful:
`nmap 192.168.x.x -p80,443 –script http-sql-injection` check for SQLi
`nmap -n -Pn -vv -O -sV –script smb-enum_,smb-ls,smb-mbenum,smb-os-discovery,smb-s_,smb-vuln_,smbv2_ -vv 192.168.1.1` SMB scripts

