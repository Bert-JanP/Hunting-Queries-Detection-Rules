# Hunt for SmartScreen events. What file was opened? Or which URL did they try to access?
----
### Defender For Endpoint

```KQL
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType has_any('SmartScreenAppWarning', 
'SmartScreenUrlWarning')
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
### Sentinel
```KQL
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType has_any('SmartScreenAppWarning', 
'SmartScreenUrlWarning')
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



