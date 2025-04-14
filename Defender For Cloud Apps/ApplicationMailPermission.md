#  List applications with Mail.* API permissions

## Query Information

#### Description
The query below lists the applications that have Mail.* Graph API permissions. These permissions are highly sensitive as it can give access to individual or shared mailboxes.

#### Risk
The Mail.* permissions grand access to mail data, which is considered highly sensitive. The permissions can be abused to get unautorized access to mailboxes.

## Defender XDR
```KQL
OAuthAppInfo
| where Permissions has "Mail."
| summarize arg_max(Timestamp, *) by OAuthAppId
| mv-expand Permissions
| extend PermissionValue = tostring(Permissions.PermissionValue), InUse = tobool(Permissions.InUse), PrivilegeLevel = tostring(Permissions.PrivilegeLevel)
| where PermissionValue startswith "Mail."
| summarize TotalMailPermissions = dcount(PermissionValue), Permissions = make_set(PermissionValue) by OAuthAppId, AppName, AppOrigin
```

## Sentinel
```KQL
OAuthAppInfo
| where Permissions has "Mail."
| summarize arg_max(TimeGenerated, *) by OAuthAppId
| mv-expand Permissions
| extend PermissionValue = tostring(Permissions.PermissionValue), InUse = tobool(Permissions.InUse), PrivilegeLevel = tostring(Permissions.PrivilegeLevel)
| where PermissionValue startswith "Mail."
| summarize TotalMailPermissions = dcount(PermissionValue), Permissions = make_set(PermissionValue) by OAuthAppId, AppName, AppOrigin
```