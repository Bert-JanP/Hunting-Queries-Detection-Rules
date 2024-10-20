# List *.All MS Graph Permissions Added

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |

#### Description
This rule detects the usage of *.All Microsoft Graph permissions that are added. *.All permissions should be scoped if possible, this ensures that the least privilege principle can still be applied. You should monitor for overpermissive applications and rare permissions that are added to applications.

#### Risk
*.All permissions are very permissive and should be limited, adversaries can use those credentials to access *.All data when those permissions are assigned.

#### References
- https://learn.microsoft.com/en-us/graph/permissions-reference
- https://github.com/f-bader/AzSentinelQueries/blob/master/HuntingQueries/GrantHighPrivilegeMicrosoftGraphPermissions.yaml

## Sentinel
```KQL
AuditLogs
| where Category == "ApplicationManagement"
| where ActivityDisplayName in ("Add delegated permission grant", "Add app role assignment to service principal")
| mv-expand TargetResources
| where TargetResources.displayName == "Microsoft Graph"
| mv-expand TargetResources.modifiedProperties
| extend InitiatedByUserPrincipalName = InitiatedBy.user.userPrincipalName
| extend AddedPermission = replace_string(tostring(TargetResources_modifiedProperties.newValue),'"','')
| extend IP = todynamic(InitiatedBy).user.ipAddress
| extend ServicePrincipalAppId = replace_string(tostring(todynamic(TargetResources).modifiedProperties[5].newValue),'"','')
| where AddedPermission endswith ".All"
| project-reorder TimeGenerated, InitiatedByUserPrincipalName, ActivityDisplayName, AddedPermission, IP, ServicePrincipalAppId
```
