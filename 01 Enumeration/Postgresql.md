while already on machine with user postgres, run:
```
psql -h 127.0.0.1 postgres
```
- will ask for pw
```
\list
```
- show databases
```
\c cozyhosting
```
- switch to database named cozyhosting
```
\d
```
- show all tables (after switching to database)
```
select * from users;
```
- show every entry from "users" row