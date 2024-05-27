# List Alert Supression Actions

## Query Information

### Description
This query lists all the supressions that have been added to Defender XDR. This gives you an overview of what rules are added, by who and why they have been added.

### References
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/introducing-the-new-alert-suppression-experience/ba-p/3562719

## Defender For Endpoint
```
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "ExclusionConfigurationAdded"
| extend Workload = tostring(parse_json(RawEventData).Workload), ResultStatus = tostring(parse_json(RawEventData).ResultStatus), ResultDescription = tostring(parse_json(RawEventData).ResultDescription)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder Timestamp, Workload, ResultDescription, ResultStatus,  InitiatedByAccountName, InitiatedByAccounttId
```
## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| where ActionType == "ExclusionConfigurationAdded"
| extend Workload = tostring(parse_json(RawEventData).Workload), ResultStatus = tostring(parse_json(RawEventData).ResultStatus), ResultDescription = tostring(parse_json(RawEventData).ResultDescription)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder TimeGenerated, Workload, ResultDescription, ResultStatus,  InitiatedByAccountName, InitiatedByAccounttId
```