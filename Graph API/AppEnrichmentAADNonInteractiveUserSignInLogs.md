# MicrosoftGraphActivityLogs App Enrichment AADNonInteractiveUserSignInLogs Based 

## Query Information

#### Description
This query enriches the *MicrosoftGraphActivityLogs* with Application information from the *AADNonInteractiveUserSignInLogs* table to get more context in the results.

This query does have a limitation, a user must have signed in to the application to show up in the logs. An alternative KQL query is available that leverages the externaldata operator to solve this issue: [App Enrichment ExternalData](./AppEnrichmentExternalData.md)

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#what-data-is-available-in-the-microsoft-graph-activity-logs
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs

## Sentinel
```KQL
let ApplicationName = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by ResourceIdentity
| project-rename ApplicationName = ResourceDisplayName
| project ApplicationName, ResourceIdentity;
MicrosoftGraphActivityLogs
// Your filter here
| lookup kind=leftouter ApplicationName on $left.AppId == $right.ResourceIdentity
| project-reorder AppId, ApplicationName
```