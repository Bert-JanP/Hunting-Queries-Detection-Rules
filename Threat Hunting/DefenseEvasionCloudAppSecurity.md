# Hunt for actions that could potentially be Defense Evasion
----
### Defender For Endpoint

```
CloudAppEvents
| where ActionType == "DefenseEvasion"
| extend Actor = parse_json(ActivityObjects).Name
| extend MachineName = parse_json(RawEventData).MachineFQDN
| project-reorder
     Actor,
     MachineName,
     ActionType,
     Application,
     IsAdminOperation,
     ActivityType,
     RawEventData

```
### Sentinel
```
CloudAppEvents
| where ActionType == "DefenseEvasion"
| extend Actor = parse_json(ActivityObjects).Name
| extend MachineName = parse_json(RawEventData).MachineFQDN
| project-reorder
     Actor,
     MachineName,
     ActionType,
     Application,
     IsAdminOperation,
     ActivityType,
     RawEventData

```



