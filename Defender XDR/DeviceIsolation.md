# List Device Isolations

## Query Information

### Description
This query lists all the device isolation activities that have been performed by Defender For Endpoint. It is good practice to review those once every x period. The query extracts multiple events from the isolation action, ssuch as which device is isolated, what isolation comment has been used and the type of isolation that has been executed.

### References
- https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender XDR
```
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "IsolateDevice"
| extend IsolatedDevice = tostring(parse_json(RawEventData).DeviceName), IsolationComment = tostring(parse_json(RawEventData).ActionComment), IsolationScope = tostring(parse_json(RawEventData).ActionScope)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
|project-reorder Timestamp, IsolatedDevice, IsolationComment, IsolationScope, InitiatedByAccountName, InitiatedByAccounttId
```
## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| where ActionType == "IsolateDevice"
| extend IsolatedDevice = tostring(parse_json(RawEventData).DeviceName), IsolationComment = tostring(parse_json(RawEventData).ActionComment), IsolationScope = tostring(parse_json(RawEventData).ActionScope)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
|project-reorder TimeGenerated, IsolatedDevice, IsolationComment, IsolationScope, InitiatedByAccountName, InitiatedByAccounttId
```
