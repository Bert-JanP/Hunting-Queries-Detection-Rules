# Hunt for activities where Hard Delete user was performed

## Query Information

#### Description
This query lists activities where a hard user delete has been performed.

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "Hard Delete user."
| extend DeletedUser = parse_json(RawEventData).ObjectId
| project
     Timestamp,
     ActionType,
     Application,
     InitiatingUser = AccountDisplayName,
     DeletedUser
```
## Sentinel
```KQL
CloudAppEvents
| where ActionType == "Hard Delete user."
| extend DeletedUser = parse_json(RawEventData).ObjectId
| project
     TimeGenerated,
     ActionType,
     Application,
     InitiatingUser = AccountDisplayName,
     DeletedUser
```
