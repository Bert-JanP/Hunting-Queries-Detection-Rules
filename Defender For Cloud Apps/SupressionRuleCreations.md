# Detect supression rule creations

### Defender For Endpoint

```
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
### Sentinel
```
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
