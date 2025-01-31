if responder doesn't recieve ldap request, check services running on port 389:
```
sudo lsof -i :389
```
- check for whats running on port 389, note PID #
```
sudo kill -9 <PID>
```
- kill that service