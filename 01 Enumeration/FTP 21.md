Anonymous login:
```
ftp <target-ip>
```
- user anonymous, password blank 

additional nmap scripts:
```
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor <target-ip>
```

spray
```
nxc ftp 192.168.1.1 -u user -p pass
```

download all FTP files with wget; useful if FTP connection fails for some reason
```
wget --recursive --ftp-user=anonymous --ftp-password=any --no-passive-ftp ftp://192.168.109.111
```

may need to disable passive mode if hangs:
```
passive
```
- toggles passive mode off or on