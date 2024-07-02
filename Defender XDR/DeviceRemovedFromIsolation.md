# Device Removed From Isolation

## Query Information

### Description
This query lists all the devices that are removed from isolation activities that have been performed by Defender For Endpoint. It is good practice to review those once every x period. The query extracts multiple events from the removal action, such as which device is isolated, what isolation comment has been used and the type of isolation that has been executed. The removal action is enriched with the original isolation information to return an overview of why the device has been isolated, by who and why it is removed from isolation and who initated the action.

### References
- https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender For Endpoint
```
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "ReleaseFromIsolation"
| extend ReleasedDevice = tostring(parse_json(RawEventData).DeviceName), ReleaseComment = tostring(parse_json(RawEventData).ActionComment)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
// Lookup Isolation Reason
| lookup kind=leftouter (CloudAppEvents
    | where Timestamp > ago(30d)
    | where ActionType == "IsolateDevice"
    | extend IsolatedDevice = tostring(parse_json(RawEventData).DeviceName), IsolationComment = tostring(parse_json(RawEventData).ActionComment), IsolationScope = tostring(parse_json(RawEventData).ActionScope)
    | project-rename IsolationInitiatedByAccountName = AccountDisplayName, IsoaltionInitiatedByAccounttId = AccountId, IsolationTime = Timestamp
    | project IsolationTime, IsolatedDevice, IsolationComment, IsolationScope, IsolationInitiatedByAccountName, IsoaltionInitiatedByAccounttId) on $left.ReleasedDevice == $right.IsolatedDevice
|project-reorder Timestamp, ReleasedDevice, ReleaseComment, InitiatedByAccountName, InitiatedByAccounttId, IsolationTime, IsolationComment, IsolationScope, IsolationInitiatedByAccountName, IsoaltionInitiatedByAccounttId
```
## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| where ActionType == "ReleaseFromIsolation"
| extend ReleasedDevice = tostring(parse_json(RawEventData).DeviceName), ReleaseComment = tostring(parse_json(RawEventData).ActionComment)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
// Lookup Isolation Reason
| lookup kind=leftouter (CloudAppEvents
    | where TimeGenerated > ago(30d)
    | where ActionType == "IsolateDevice"
    | extend IsolatedDevice = tostring(parse_json(RawEventData).DeviceName), IsolationComment = tostring(parse_json(RawEventData).ActionComment), IsolationScope = tostring(parse_json(RawEventData).ActionScope)
    | project-rename IsolationInitiatedByAccountName = AccountDisplayName, IsoaltionInitiatedByAccounttId = AccountId, IsolationTime = TimeGenerated
    | project IsolationTime, IsolatedDevice, IsolationComment, IsolationScope, IsolationInitiatedByAccountName, IsoaltionInitiatedByAccounttId) on $left.ReleasedDevice == $right.IsolatedDevice
|project-reorder TimeGenerated, ReleasedDevice, ReleaseComment, InitiatedByAccountName, InitiatedByAccounttId, IsolationTime, IsolationComment, IsolationScope, IsolationInitiatedByAccountName, IsoaltionInitiatedByAccounttId
```