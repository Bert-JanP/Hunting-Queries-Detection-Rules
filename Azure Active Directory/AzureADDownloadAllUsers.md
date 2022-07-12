# Operation download all users in Azure Active directory performed
----
### Sentinel
```
AuditLogs
| where OperationName contains "Download users"
| extend InitiatedByInfo = parse_json(InitiatedBy).['user']
| extend InitiatedByUser = InitiatedByInfo.userPrincipalName
| project-reorder OperationName, ResultDescription, InitiatedByUser, TimeGenerated

```
