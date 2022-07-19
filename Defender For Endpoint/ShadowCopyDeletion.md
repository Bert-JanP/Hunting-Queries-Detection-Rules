# Rule triggers when a known ransomware command is used to delete shadowcopies
----
### Defender For Endpoint

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
### Sentinel
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



