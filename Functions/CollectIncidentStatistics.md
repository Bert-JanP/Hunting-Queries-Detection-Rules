# Function: CollectIncidentStatistics()

## Query Information

#### Description
This function returns the severity statistics of Sentinel or XDR.

## Defender XDR
```
let CollectIncidentStatistics = (TimeSpan: timespan) {
    AlertInfo
    | where TimeGenerated > ago(TimeSpan)
    | summarize arg_max(TimeGenerated, *) by AlertId
    | summarize TotalIncidents = count() by Severity
};
// Example
CollectIncidentStatistics(10d)
```
## Sentinel
```
let CollectIncidentStatistics = (TimeSpan: timespan) {
    SecurityIncident
    | where TimeGenerated > ago(TimeSpan)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | summarize TotalIncidents = count() by Severity
};
// Example
CollectIncidentStatistics(10d)
```

