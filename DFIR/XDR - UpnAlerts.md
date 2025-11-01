# Device Alerts

## Query Information

#### Description
This query lists all the alerts that have triggered based on a specific UPN in the selected *TimeFrame*.

## Defender XDR
```KQL
let Upn = 'user@test.com';
let TimeFrame = 7d;
AlertEvidence
| where Timestamp > ago(TimeFrame)
| where EntityType in~ ('User', 'Mailbox')
| summarize arg_max(Timestamp, *) by AlertId
| project AlertId, EntityType
| join kind=inner AlertInfo on AlertId
| extend AlertLink = strcat('https://security.microsoft.com/alerts/', AlertId)
| project-reorder Timestamp, EntityType, Title, Category, Severity, DetectionSource, AlertLink
| sort by Timestamp desc
```