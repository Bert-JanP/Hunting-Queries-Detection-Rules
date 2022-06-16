# Hunt for SmartScreen events. What file was opened? Or which URL did they try to access?
----
### Defender For Endpoint

```
DeviceEvents
| where Timestamp > ago(7d)
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
```
DeviceEvents
| where TimeGenerated > ago(7d)
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



