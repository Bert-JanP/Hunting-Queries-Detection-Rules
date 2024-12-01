# Detect when Regsvr32.exe is created as subprocess by an Office Application

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.010 | System Binary Proxy Execution: Regsvr32 |Access https://attack.mitre.org/techniques/T1218/010/ |

#### Description
Regsvr32 can be abused to proxy execution of malicious code. It can be spawned from a Office Application to infect the system with malware. The Office applications would not spawn Regsvr32 themselfs.

#### References
- https://redcanary.com/threat-detection-report/threats/TA551/
- https://threatpost.com/cybercriminals-windows-utility-regsvr32-malware/178333/

## Defender XDR
```
let OfficeApplications = dynamic(['winword.exe', 'powerpnt.exe', 'excel.exe']);
DeviceProcessEvents
| where FileName == "regsvr32.exe"
| where InitiatingProcessFileName has_any (OfficeApplications)
| project
     Timestamp,
     DeviceName,
     AccountName,
     AccountDomain,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     InitiatingProcessFileName
```
## Sentinel
```
let OfficeApplications = dynamic(['winword.exe', 'powerpnt.exe', 'excel.exe']);
DeviceProcessEvents
| where FileName == "regsvr32.exe"
| where InitiatingProcessFileName has_any (OfficeApplications)
| project
     TimeGenerated,
     DeviceName,
     AccountName,
     AccountDomain,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     InitiatingProcessFileName
```



