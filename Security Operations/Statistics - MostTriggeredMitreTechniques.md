# Most Triggered Mitre Techniques

## Query Information

#### Description
The results of this query provide insight in the top 10 MITRE ATT&CK Techniques that have been triggered in the past 10 days. This can indicate that adversaries use specific techniques to gain access to your environment. On the otherhand if this information is combined with FP/BP statistics it can give insight into the detections that need to be improved. 

## Defender For Endpoint
```KQL
let timeframe = 7d;
AlertInfo
| where Timestamp > ago(timeframe)
// Collect the last entry of each alert
| summarize arg_max(Timestamp, *) by AlertId
// Ensure that events with multiple techniques can be counted
| extend MitreTechnique = todynamic(AttackTechniques)
| mv-expand MitreTechnique
| summarize TriggerCount = count() by tostring(MitreTechnique)
| top 10 by TriggerCount

```
## Sentinel
```KQL
// Timeframe to collect incident statistics
let timeframe = 7d;
SecurityIncident
| where TimeGenerated > ago(timeframe)
// Collect the last entry of each alert
| summarize arg_max(TimeGenerated, *) by IncidentNumber
// Ensure that events with multiple techniques can be counted
| extend MitreTechnique = todynamic(AdditionalData).techniques
| mv-expand MitreTechnique
| summarize TriggerCount = count() by tostring(MitreTechnique)
| top 10 by TriggerCount
```