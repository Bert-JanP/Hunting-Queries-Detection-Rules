# List *.All MS Graph Permissions Added by application.

## Query Information

#### Description
This rule detects the usage of *.All Microsoft Graph permissions that are added. *.All permissions should be scoped if possible, this ensures that the least privilege principle can still be applied. You should monitor for overpermissive applications and rare permissions that are added to applications. This query summarize the results for each ServicePrincipalAppId, especially applications that have been granted multiple *.All permissions should be investigated. 

#### Risk
*.All permissions are very permissive and should be limited, adversaries can use those credentials to access *.All data when those permissions are assigned.

#### References
- https://learn.microsoft.com/en-us/graph/permissions-reference
- https://github.com/f-bader/AzSentinelQueries/blob/master/HuntingQueries/GrantHighPrivilegeMicrosoftGraphPermissions.yaml
- [*.All Graph Permissions Added](./AllGraphPermissionsAdded.md)

## Sentinel
```KQL
AuditLogs
| where Category == "ApplicationManagement"
| where ActivityDisplayName in ("Add delegated permission grant", "Add app role assignment to service principal")
| mv-expand TargetResources
| where TargetResources.displayName == "Microsoft Graph"
| mv-expand TargetResources.modifiedProperties
| extend InitiatedByUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| extend AddedPermission = replace_string(tostring(TargetResources_modifiedProperties.newValue),'"','')
| extend IP = tostring(todynamic(InitiatedBy).user.ipAddress)
| extend ServicePrincipalAppId = iff(OperationName == "Add delegated permission grant", replace_string(tostring(todynamic(TargetResources).modifiedProperties[2].newValue),'"','') , replace_string(tostring(todynamic(TargetResources).modifiedProperties[5].newValue),'"',''))
| where AddedPermission endswith ".All"
| summarize Permissions = make_set(AddedPermission) by ServicePrincipalAppId, IP, InitiatedByUserPrincipalName
| extend TotalPermissions = array_length(Permissions)
| project TotalPermissions, ServicePrincipalAppId, InitiatedByUserPrincipalName, IP, Permissions
| sort by TotalPermissions
```
