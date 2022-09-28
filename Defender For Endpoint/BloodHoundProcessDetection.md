# BloodHound Detection based on processes

Based on Threat Report by RedCanary: [link](https://redcanary.com/threat-detection-report/threats/bloodhound/)

### Defender For Endpoint
```
let BloodhoundCommands = dynamic(['-collectionMethod', 'invoke-bloodhound' ,'get-bloodHounddata']);
DeviceProcessEvents
| where ProcessCommandLine has_any (BloodhoundCommands)
| project
     Timestamp,
     DeviceName,
     AccountName,
     AccountDomain,
     ProcessCommandLine,
     FileName,
     InitiatingProcessCommandLine,
     InitiatingProcessFileName
```
### Sentinel
```
let BloodhoundCommands = dynamic(['-collectionMethod', 'invoke-bloodhound' ,'get-bloodHounddata']);
DeviceProcessEvents
| where ProcessCommandLine has_any (BloodhoundCommands)
| project
     TimeGenerated,
     DeviceName,
     AccountName,
     AccountDomain,
     ProcessCommandLine,
     FileName,
     InitiatingProcessCommandLine,
     InitiatingProcessFileName
```



