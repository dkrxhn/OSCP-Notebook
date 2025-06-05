```
curl -o /home/daniel/desktop/hsploit.html https://hsploit.com
```
```
curl -o ubuntuIso.iso http://ubuntu.mirror.ac.ke/ubuntu-release.iso
```
- download a link/file and save it as a specific file

```
curl -O http://ubuntu.mirror.ac.ke/ubuntu-release.iso
```
- download file with original name

```
curl -L http://hsploit.com
```
- will return the redirect, which is to the ***https*** site in this case

```
curl -I https://hsploit.com
```
- returns response header

```
curl -v https://hsploit.com
```
- returns entire tls handshake

```
curl --data "log=admin&pwd=password" https://wordpress.com/wp-login.php
```
- specify own values to login parameters

```
curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@//home/user/Documents/OffSec/Proving_Grounds/Play/Amaterasu/text.txt" -F filename=”/tmp/test.txt” 
```
- submit POST request to upload a file