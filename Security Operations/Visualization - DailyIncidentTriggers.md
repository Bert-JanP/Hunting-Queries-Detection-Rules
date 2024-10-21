# Visualize the daily incident triggers

## Query Information

#### Description
Visualize the daily triggers in MDE or Sentinel in a columnchart. This can give insight into spikes in the amount of triggers.

## Defender XDR
```KQL
AlertInfo
| where Timestamp > ago(30d)
// Collect the first entry of each alert
| summarize arg_min(Timestamp, *) by AlertId
| summarize Total = count() by bin(Timestamp, 1d)
| render columnchart with(title="Incident triggers last 30 days")

```
## Sentinel
```KQL
SecurityIncident
| where TimeGenerated > ago(30d)
// Collect the first entry of each alert
| summarize arg_min(TimeGenerated, *) by IncidentNumber
| summarize Total = count() by bin(CreatedTime, 1d)
| render columnchart with(title="Incident triggers last 30 days")
```
