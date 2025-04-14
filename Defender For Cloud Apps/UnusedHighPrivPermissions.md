# Identify unused high privileged application permissions

## Query Information

#### Description
The query below identifies unused high privileged application permissions. These permissions can be revoked from the application to adhere to the least privileged principle.

#### Risk
Having unused permissions is not in line with assigning least privilige to applications. Unused applications can be abused if adversaries get access to the application.

## Defender XDR
```KQL
OAuthAppInfo
| summarize arg_max(Timestamp, *) by OAuthAppId
| mv-expand Permissions
| extend PermissionValue = tostring(Permissions.PermissionValue), InUse = tobool(Permissions.InUse), PrivilegeLevel = tostring(Permissions.PrivilegeLevel)
| where InUse == false and PrivilegeLevel == "High"
| summarize TotalMailPermissions = dcount(PermissionValue), Permissions = make_set(PermissionValue) by OAuthAppId, AppName, AppOrigin
```

## Sentinel
```KQL
OAuthAppInfo
| summarize arg_max(TimeGenerated, *) by OAuthAppId
| mv-expand Permissions
| extend PermissionValue = tostring(Permissions.PermissionValue), InUse = tobool(Permissions.InUse), PrivilegeLevel = tostring(Permissions.PrivilegeLevel)
| where InUse == false and PrivilegeLevel == "High"
| summarize TotalMailPermissions = dcount(PermissionValue), Permissions = make_set(PermissionValue) by OAuthAppId, AppName, AppOrigin
```
