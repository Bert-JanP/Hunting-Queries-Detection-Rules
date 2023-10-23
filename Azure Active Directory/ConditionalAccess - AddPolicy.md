# Conditional Access Policy Addition

## Query Information

#### Description
This KQL query lists all conditional access policies that have been added.

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-consumer-accounts
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/


## Sentinel
```KQL
AuditLogs
| where OperationName == "Add conditional access policy"
| extend DeletedPolicy = TargetResources.[0].displayName, Actor = InitiatedBy.user.userPrincipalName
| project TimeGenerated, Actor, DeletedPolicy, TargetResources
```