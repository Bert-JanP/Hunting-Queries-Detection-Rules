# List supression rule creations

## Query Information

#### Description
This query lists supression rule creations.

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "Write AlertsSuppressionRules"
| project
     Timestamp,
     ActionType,
     Application,
     AccountId,
     AccountDisplayName,
     CreatedSupresionRule = ObjectName
```
## Sentinel
```KQL
CloudAppEvents
| where ActionType == "Write AlertsSuppressionRules"
| project
     TimeGenerated,
     ActionType,
     Application,
     AccountId,
     AccountDisplayName,
     CreatedSupresionRule = ObjectName
```
