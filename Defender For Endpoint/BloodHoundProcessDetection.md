# BloodHound Detection

## Query Information

#### Description
This query detects the use of bloodhound based on the processes it creates. This detection is based on Threat Report by RedCanary.

#### References
- https://redcanary.com/threat-detection-report/threats/bloodhound/

## Defender XDR
```KQL
// List with known bloodhound executions
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
## Sentinel
```KQL
// List with known bloodhound executions
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



