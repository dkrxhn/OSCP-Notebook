```
xxd accounts.xlsx | head
```
- hex

```
file accounts.xlsx
```
- file info (should say "Excel 2017" etc but if says Zip, continue down)

```
binwalk accounts.xlsx
```
- look for `shareStrings.xml`

```
strings accounts.xlsx | less
```
- extract any readable text (sometimes things hidden)

```
trid Backup.zip
```
- identify obscure file formats (even though says .zip, running `file BackUp.zip` returns 'data')

```
cat BackUp.zip | ent
```
- tests entropy: closer to 8 means more likely compressed/encrypted
### .xlsx
- Essentially zip files. trying extracting contents:
```
unzip accounts.xlsx
```
### Extract macro info from .xlsm
```
olevba filename.xlsm
```

#### Images
if png, run `strings`
if jpg, try `strings` or bruteforce with stegseek
```
stegseek image.jpg /usr/share/wordlists/rockyou.txt
```

#### 7z
```
7z x wapt-backup-sunday.7z
```
- `x` extract with full path