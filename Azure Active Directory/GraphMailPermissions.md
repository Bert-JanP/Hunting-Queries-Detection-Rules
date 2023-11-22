# List MS Graph Mail Permissions Added

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions| https://attack.mitre.org/techniques/T1098/002/ |

#### Description
The Graph API can be used to read and send mail amongst other actions. Escpecially the Mail*.All permissions are very priviliged and should be scoped to a certain mailbox only (if possible). This query can both be used to assess the current added permissions as well as to detect malicious mail permission that are added to applications.

#### Risk
Adversaries can use applications to read sentitive mails or to send out malicious mails from your domain.

#### References
- https://learn.microsoft.com/en-us/graph/permissions-reference
- https://github.com/f-bader/AzSentinelQueries/blob/master/HuntingQueries/GrantHighPrivilegeMicrosoftGraphPermissions.yaml
- https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access

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
| where AddedPermission has_all ("Mail", ".")
| summarize Permissions = make_set(AddedPermission) by ServicePrincipalAppId, IP, InitiatedByUserPrincipalName
| extend TotalPermissions = array_length(Permissions)
| project TotalPermissions, ServicePrincipalAppId, InitiatedByUserPrincipalName, IP, Permissions
| sort by TotalPermissions
```