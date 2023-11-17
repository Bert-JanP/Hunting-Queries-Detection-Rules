# List All Role Additions

## Query Information

#### Description
This query list all role additions that have been performed in your tenant. See the Microsoft Link for the default roles that exsits in Azure Active Directory. They contain reader, operator, administrator and other roles. It is good practice to gain insight into the roles that have been assigned to accounts. Based on this query you can build a detection for specific roles with high priviliges such as Global Admin, Security Admin or Exchange Admin.

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference

## Sentinel
```KQL
AuditLogs
| where OperationName == 'Add member to role'
// If you do want to show PIM activations remove this filter
| where Identity != 'MS-PIM'
| extend RoleLine = tostring(extract(@'Role.DisplayName(.*?)"}', 1, tostring(TargetResources)))
| extend Role = tostring(extract(@'newValue":"\\"(.*?)\\', 1, RoleLine)), userPrincipalName = parse_json(TargetResources).[0].userPrincipalName
| project TimeGenerated, Role, OperationName, userPrincipalName, Identity
```
