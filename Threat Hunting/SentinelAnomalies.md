# Hunt for anomalies in Sentinel

### Sentinel

```
let TimeFrame = 7d;
Anomalies
| where TimeGenerated > ago(TimeFrame)
| project-rename ['Anomaly Reason'] = Description
| project-reorder TimeGenerated, ['Anomaly Reason'], Entities, RuleName, 
Tactics
```