# List all AuditLog activities of a user

## Sentinel
```KQL
let AccountUPN = "test@kqlquery.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
AuditLogs
| where TimeGenerated > ago(SearchWindow)
| extend InitiatingUser = parse_json(InitiatedBy.user)
| extend InitatingUPN = parse_json(InitiatingUser).userPrincipalName
| where InitatingUPN == AccountUPN
| project-reorder TimeGenerated, InitatingUPN, OperationName, ResultDescription, ActivityDisplayName, Resource, Result
```



