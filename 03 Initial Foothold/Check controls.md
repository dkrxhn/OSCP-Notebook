## Windows
#### Defender
```powershell
Get-MpComputerStatus
```
- check if Windows Defender is running

---
#### AppLocker
```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
- check AppLocker rules
	- Alternate powershell executable locations besides `%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`
	- `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
	- `PowerShell_ISE.exe`

---
#### Constrained Language Mode
```powershell
$ExecutionContext.SessionState.LanguageMode
```
- check for Constrained Language Mode

---
#### LAPS
```powershell
Find-LAPSDelegatedGroups
```
- check OUs where LAPS is deployed and the groups delegated permission to view the LAPS passwords
```powershell
Find-AdmPwdExtendedRights
```
- check users/groups that have "Extended Rights" to read LAPS passwords on each machine individually, even if they're not in the delegated LAPS group
	- These users might not be in the usual `LAPS Admins` or `Domain Admins` groups and could be easy targets\
```powershell
Get-LAPSComputers
```
- list computers with LAPS enabled and shows their current local admin pw and expiration date for that current password
	- will only see passwords here if your current user has the necessary read access
	- 