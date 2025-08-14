# GraphAPIAuditEvents User Enrichment

## Query Information

#### Description
This query enriches the *MicrosoftGraphActivityLogs* with userinformation from the *IdentityInfo* table to get more context in the results.

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#what-data-is-available-in-the-microsoft-graph-activity-logs
- https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityinfo-table?view=o365-worldwide
- https://kqlquery.com/posts/graphactivitylogs/

## Defender XDR
```KQL
GraphAPIAuditEvents
| where EntityType == "user"
| lookup kind=leftouter (IdentityInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | project AccountObjectId, AccountDisplayName, AccountUpn)
    on $left.AccountObjectId == $right.AccountObjectId
| project-reorder AccountDisplayName, AccountUpn, RequestMethod, RequestUri
```
