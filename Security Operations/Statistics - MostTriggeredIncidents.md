# Most Triggered Incidents

## Query Information

#### Description
The results of this query provide insight in the top 10 incidents that have triggered in your selected *timeframe*, this can give indications on which incidents should be addressed to limit potential false positives.

## Defender For Endpoint
```
// Timeframe to collect incident statistics
let timeframe = 7d;
AlertInfo
| where Timestamp > ago(timeframe)
// Collect the first entry of each alert
| summarize arg_min(Timestamp, *) by AlertId
// Get the alert statistics
| summarize Triggers = count(), AlertIds = make_set(AlertId) by Title
| top 10 by Triggers

```
## Sentinel
```
let timeframe = 7d;
SecurityIncident
| where TimeGenerated > ago(timeframe)
// Collect the first entry of each alert
| summarize arg_min(TimeGenerated, *) by IncidentNumber
// Get the alert statistics
| summarize Triggers = count(), AlertIds = make_set(IncidentNumber) by Title
| top 10 by Triggers
```