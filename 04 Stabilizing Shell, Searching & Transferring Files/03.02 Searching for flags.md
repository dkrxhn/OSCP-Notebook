powershell
```
Get-ChildItem -Path C:\ -Filter local.txt -Recurse -ErrorAction SilentlyContinue
```

```
Get-ChildItem -Path C:\ -Filter proof.txt -Recurse -ErrorAction SilentlyContinue
```

cmd
```
dir C:\local.txt /s /b
```

```
dir C:\proof.txt /s /b
```

bash
```
find / -type f -name "user.txt" 2>/dev/null
```

```
find / -type f -name "proof.txt" 2>/dev/null
```

```
find . -name user.txt -exec cat {} \;
```
- from `/home`

**searching for files**
```
dir C:\Users\Administrator\*.txt /s /b
```
- search for keepass database files

recurse through every directory and display the files
```
ls -recurse .
```
- in `C:\Users\Raven` for example, it would show all the directories that contain files and list them