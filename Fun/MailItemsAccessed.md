```KQL
union OfficeActivity, CloudAppEvents
| where TimeGenerated > ago(30d)
| extend Operation = coalesce(ActionType, Operation)
| where Operation == "MailItemsAccessed"
| summarize TotalEvents = count(), TotalCloudAppsEvents = countif(Type == "CloudAppEvents"), TotalUALEvents = countif(Type == "OfficeActivity") by bin(TimeGenerated, 1d)
| extend EqualLogs = iff(TotalCloudAppsEvents == TotalUALEvents, true, false)
```