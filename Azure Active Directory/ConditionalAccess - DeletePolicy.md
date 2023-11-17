# Deletion Conditional Access Policy

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1556 | Modify Authentication Process | https://attack.mitre.org/techniques/T1556/ |

#### Description
This KQL query lists all conditional access policies that have been deleted. The modification of authentication processes can be used to create persistence on an cloud account.

#### Risk
Adveries can delete CA policies to get persistence.

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/architecture/security-operations-consumer-accounts
- https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/


## Sentinel
```KQL
AuditLogs
| where OperationName == "Delete conditional access policy"
| extend DeletedPolicy = TargetResources.[0].displayName, Actor = InitiatedBy.user.userPrincipalName
| project TimeGenerated, Actor, DeletedPolicy, TargetResources
```
