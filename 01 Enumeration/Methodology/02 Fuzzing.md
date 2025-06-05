Feroxbuster:
```
feroxbuster -u http://10.10.30.203 -w /usr/share/wordlists/dirb/common.txt -n
```
- quickie (less than a minute)
```
feroxbuster -u http://10.10.21.22 -w /usr/share/wordlists/dankyou_wordlist.txt
```
- custom wordlist combining the 3 below wordlists, no dupes
```
feroxbuster -u http://10.129.208.228:50000/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt 
```
- make sure to also use non-lowercast.text:
```
feroxbuster -u https://nagios.monitored.htb/nagiosxi/api -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -k -m GET,POST
```
- adding GET and POST requests
```
feroxbuster -u http://10.129.208.228:50000/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```
feroxbuster -u http://10.129.208.228:50000/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
 - this ones includes .git
 
 include php & html extensions:
 ```
feroxbuster -u https://streamio.htb -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -k
```
- `-k` is useful for https to ignore cert verification
include headers:
```
feroxbuster -u http://dev.siteisup.htb -w /usr/share/wordlists/dankyou_wordlist.txt -H 'Special-Dev: only4dev' 
```
- -H 'Header-Name: Header-Value'
if too many results from ferox, try just top level directories:
```
feroxbuster -u http://siteisup.htb -n
```
- `-n` is for no recursion
can also use gobuster:
```
gobuster dir -u http://10.129.41.119/nibbleblog/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -x php,txt
```

if too many of a status code, filter out with `-C`
```
feroxbuster -u http://usage.htb -C 503 
```
- ignores any 503 responses

wfuzz for subdomains:
```
wfuzz -u http://10.129.228.102 -H "Host: FUZZ.mentor.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
- if there's a lot of false positives, filter them out based on the number of chars (the # Ch after the `--hh`)
```
wfuzz -u http://10.129.228.120 -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 7069
```
- in the above example ch # of responses is 7069
- can also filter based off code/lines/words/chars via `--hc/hl/hw/hh`
```
wfuzz -u http://10.129.228.102 -H "Host: FUZZ.mentor.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 26
```

- if domain is found with nmap scan (or other means), make sure to put in /etc/hosts and include in this command:
```
wfuzz -u http://streamio.htb -H "Host: FUZZ.streamio.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```
	- also make sure to try 443 https if port is open
- once subdomain is found, make sure to add it to /etc/hosts as well

wfuzz for parameter names:
```
wfuzz -u https://streamio.htb/admin/\?FUZZ\= -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -H "Cookie: PHPSESSID=jtde06u71uq4t7pvs59b8iis1o" --hh 1678
```
- need `\` before the `?` otherwise get zsh error
- include cookie as `PHPSESSID=jtde06u71uq4t7pvs59b8iis1o` from left-click webpage > inspect > storage

if any subdomain is found, try running feroxbuster on it for subdirectories
```
feroxbuster -u http://api.mentorquotes.htb/admin/ --no-recursion --methods GET,POST
```
- `--no-recursion` only shows top level directories
- `--methods GET,POST` does both GET & POST requests