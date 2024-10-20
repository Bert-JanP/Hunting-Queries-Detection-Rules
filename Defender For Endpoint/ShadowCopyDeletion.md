# Known Shadow Copy Delete command executed

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1490 | Inhibit System Recovery |https://attack.mitre.org/techniques/T1490|

#### Description
This rule triggers when a known ransomware command is used to delete shadowcopies. A shadow copy is a backup or snapshot of a system. When this is deleted and a ransomware actor deploys ransomware it will not be possible to return to a previous stage.

#### Risk
An advasary removes the shadow copy before deploying ransomware to ensure that you cannot go back to a previous state.

#### References
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows
- https://redcanary.com/blog/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies

## Defender XDR
```
let CommonRansomwareExecutionCommands = dynamic([@'vssadmin.exe delete shadows /all /quiet', 
@'wmic.exe shadowcopy delete', @'wbadmin delete catalog -quiet', 
@'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}',
@'del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk', 
@'wbadmin delete systemstatebackup -keepVersions:0', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /enable >nul 2>&1', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /f >nul 2>&1']);
DeviceProcessEvents
| where ProcessCommandLine has_any (CommonRansomwareExecutionCommands)
| project-reorder Timestamp, ProcessCommandLine, DeviceName, AccountName
```
## Sentinel
```
let CommonRansomwareExecutionCommands = dynamic([@'vssadmin.exe delete shadows /all /quiet', 
@'wmic.exe shadowcopy delete', @'wbadmin delete catalog -quiet', 
@'Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}',
@'del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk', 
@'wbadmin delete systemstatebackup -keepVersions:0', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable', 
@'schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /enable >nul 2>&1', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f', 
@'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1', 
@'reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /f >nul 2>&1']);
DeviceProcessEvents
| where ProcessCommandLine has_any (CommonRansomwareExecutionCommands)
| project-reorder TimeGenerated, ProcessCommandLine, DeviceName, AccountName
```



