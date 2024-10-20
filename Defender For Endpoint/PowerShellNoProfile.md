# PowerShell No Profile (APT 28)

## Query Information

#### Description
This query can be used to detect behaviour that APT28 uses in their attacks. The Ukrainian CERT has shared the following commands executed by APT28 which could be detected by this KQL query. 

```PowerShell
cmd /C start powershell.exe -w hid -nop -c "%LOCALAPPDATA%\python\python-3.10.0-embed-amd64\python.exe %LOCALAPPDATA%\python\python-3.10.0-embed-amd64\Client.py"
powershell.exe -w hid -nop -c %LOCALAPPDATA%\python\python-3.10.0-embed-amd64\python.exe %LOCALAPPDATA%\python\python-3.10.0-embed-amd64\Client.py
powershell.exe -w hid -nop -c Expand-Archive -Force %PROGRAMDATA%\python.zip %PROGRAMDATA%\python
powershell.exe -w hid -nop -c start "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SystemUpdate.lnk"
powershell.exe -w hid -nop gpresult /z
powershell.exe -w hid -nop gpupdate
```

The *-w hid -nop (-c)* can be explained:
-w: This specifies the window style for the PowerShell window that will be opened. hid is not a standard PowerShell window style.

-nop: This stands for "no profile". It tells PowerShell not to load the user profile (e.g., $PROFILE) during startup.

-c: This parameter allows you to specify a command or script to run within PowerShell.

#### Risk
APT28 has access to your environment and executes malicious commands.

#### References
- https://cert.gov.ua/article/6276894
- https://attack.mitre.org/groups/G0007/
- https://medium.com/cyberscribers-exploring-cybersecurity/apt28-from-initial-damage-to-domain-controller-threats-in-an-hour-cert-ua-8399-1944dd6edcdf

## Defender XDR
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_all ("-nop", "powershell.exe")
| summarize TotalCommands = dcount(ProcessCommandLine), ExecutedCommands = make_set(ProcessCommandLine) by DeviceName
```
## Sentinel
```KQL
DeviceProcessEvents
| where ProcessCommandLine has_all ("-nop", "powershell.exe")
| summarize TotalCommands = dcount(ProcessCommandLine), ExecutedCommands = make_set(ProcessCommandLine) by DeviceName
```
