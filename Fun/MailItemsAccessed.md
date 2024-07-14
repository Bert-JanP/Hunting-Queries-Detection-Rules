This query compares the *MailItemsAccessed* from OfficeActivity and CloudAppEvents and returns the column *EqualLogs* that shows if the logs have the same amount of entries. This should be the case, but does not seem to be the case in multiple environment. The CloudAppEvents table seems to log a few duplicate entries.

Also see: https://x.com/BertJanCyber/status/1806350833505775775

```KQL
union OfficeActivity, CloudAppEvents
| where TimeGenerated > ago(30d)
| extend Operation = coalesce(ActionType, Operation)
| where Operation == "MailItemsAccessed"
| summarize TotalEvents = count(), TotalCloudAppsEvents = countif(Type == "CloudAppEvents"), TotalUALEvents = countif(Type == "OfficeActivity") by bin(TimeGenerated, 1d)
| extend EqualLogs = iff(TotalCloudAppsEvents == TotalUALEvents, true, false)
```