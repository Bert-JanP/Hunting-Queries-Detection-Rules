# List SmartScreen Events

## Query Information

#### Description
This query lists all SmartScreen related events.

#### References
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/

## Defender XDR
```KQL
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType startswith "SmartScreen"
| extend SmartScreenTrigger = iff(ActionType == "SmartScreenUrlWarning", 
RemoteUrl, FileName)
| extend ReasonForTrigger = parse_json(AdditionalFields).Experience
| project
     Timestamp,
     DeviceName,
     ActionType,
     SmartScreenTrigger,
     ReasonForTrigger,
     InitiatingProcessCommandLine
```
## Sentinel
```KQL
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType startswith "SmartScreen"
| extend SmartScreenTrigger = iff(ActionType == "SmartScreenUrlWarning", 
RemoteUrl, FileName)
| extend ReasonForTrigger = parse_json(AdditionalFields).Experience
| project
     TimeGenerated,
     DeviceName,
     ActionType,
     SmartScreenTrigger,
     ReasonForTrigger,
     InitiatingProcessCommandLine
```
