# Detect when Regsvr32.exe is created as subprocess by an Office Application

Based on Threat Report by RedCanary: [link](https://redcanary.com/threat-detection-report/threats/TA551/)

### Defender For Endpoint
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
### Sentinel
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



