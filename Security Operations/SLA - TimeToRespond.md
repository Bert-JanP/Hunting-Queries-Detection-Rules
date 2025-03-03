# SLA Time To Respond

## Query Information

#### Description
The query below can be used to validate if the agreed SLA for time to respond is met by your analysts. The query used a datatable *SLA_Variables* that you can adjust to your time to responde (minutes).

This query is a basis and will return all closed incident and if they met the agreed SLA. Based on this query additional aggregation or the rendering of charts can be performed.

#### References
- https://github.com/Bert-JanP/Sentinel-Automation/tree/main/SLA%20Reporting%20Mail%20Report
- https://github.com/Bert-JanP/Sentinel-Automation/tree/main/Workbooks/SLA%20Reporting

## Sentinel
```KQL
// Prepare Data (Additonal Context)
let SLA_Variables = datatable (Severity: string, TimeToRespond: int, TimeToContainmentMinutes: int, UpdateIntervalMinutes: int)
[
    "High", 60, 1440, 60,
    "Medium", 120, 2880, 120,
    "Low", 240, 4320, 240,
    "Informational", 480, 10080, 480
];
// Collect Data
SecurityIncident
| where CreatedTime > ago(7d)
| where Status == "Closed"
// Prepare Data (Parsing)
| extend AssignedAnalyst = Owner.userPrincipalName
// Prepare Data (Standardize)
| extend StandardizedAssignedAnalyst = tolower(Owner.userPrincipalName)
| extend LocalIncidentCreationTime = datetime_local_to_utc(CreatedTime, 'Europe/Copenhagen')
// Prepare Data (Aggregation & Statistics)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
// Prepare Data (Additonal Context)
| join kind=inner SLA_Variables on Severity
| extend TimeToRespondToIncident = datetime_diff('minute', FirstModifiedTime, CreatedTime)
| extend MetSLA = TimeToRespondToIncident <= TimeToRespond
| where isnotempty(MetSLA)
// Present Data
| project IncidentNumber, Title, Severity, StandardizedAssignedAnalyst, TimeToRespondToIncident, MetSLA
```
