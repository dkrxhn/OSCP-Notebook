Anonymous login:
```
ftp <target-ip>
```
- user anonymous, password blank 

If connect, check if uploading files works
```
put <local-file-name>
```
- attempt normal upload attacks like executing php it via url/uploads/

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
wget --recursive --ftp-user=anonymous --ftp-password=any --no-passive-ftp ftp://192.168.157.249
```

may need to disable passive mode if hangs:
```
passive
```
- toggles passive mode off or on

```
hydra -l alfredo -e nsr ftp://192.168.152.249
```
- checks null passwords, username as password, and reverse of username as password