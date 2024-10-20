# WMIC Remote Command Execution

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218 | System Binary Proxy Execution| https://attack.mitre.org/techniques/T1218/ |
| T1047 | Windows Management Instrumentation | https://attack.mitre.org/techniques/T1047/ |

#### Description
Adversaries can use WMIC to remotely execute commands, WMIC has been used various times in the wild by different adversaries. WMI is an administration feature that provides a uniform environment to access Windows system components. The WMI service enables both local and remote access. WMIC has been used to call remote processes to perform lateral movement. This query detects all WMIC queries that contain a IP address, which in most cases would be a remote IP address. WMIC can perform various tasks, such as creating processes, executing remote calls and executing (remote) scripts. 

#### Risk
An actor uses WMIC to remotely execute malicious commands. 

#### References
- https://lolbas-project.github.io/lolbas/Binaries/Wmic/
- https://web.archive.org/web/20230728141353/https://research.nccgroup.com/2021/01/12/abusing-cloud-services-to-fly-under-the-radar/
- https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic

## Defender XDR
```
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceProcessEvents
| where FileName =~ "WMIC.exe"
// Extract IP Addresses from the commandline
| extend RemoteIP = extract(IPRegex, 0, ProcessCommandLine)
// Only select commandlines that have a remote IP
| where isnotempty(RemoteIP)
// Filter Localhost, more IPs can be added to this list if they generate false postives.
| where not( RemoteIP in ('127.0.0.1'))
| project Timestamp, DeviceName, ProcessCommandLine, RemoteIP
```
## Sentinel
```
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
DeviceProcessEvents
| where FileName =~ "WMIC.exe"
// Extract IP Addresses from the commandline
| extend RemoteIP = extract(IPRegex, 0, ProcessCommandLine)
// Only select commandlines that have a remote IP
| where isnotempty(RemoteIP)
// Filter Localhost, more IPs can be added to this list if they generate false postives.
| where not( RemoteIP in ('127.0.0.1'))
| project TimeGenerated, DeviceName, ProcessCommandLine, RemoteIP
```

