# Hunt for activities where Hard Delete user was performed
----
### Defender XDR

```
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
### Sentinel
```
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
