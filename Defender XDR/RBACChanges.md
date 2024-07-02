# Audit RBAC Changes Defender XDR

## Query Information

### Description
The query below can be used to monitor RBAC changes in Defender XDR. This query list additions, deletions and changes, if you only want to monitor specific actions you can enhance the query by filtering on the actiontype.

### References
- https://learn.microsoft.com/en-us/defender-xdr/m365d-permissions
- https://learn.microsoft.com/en-us/defender-endpoint/rbac
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender For Endpoint
```
CloudAppEvents
| extend Workload = tostring(parse_json(RawEventData).Workload)
| where Workload contains "Defender"
| where ActionType endswith "Role"
| extend RoleName = tostring(parse_json(RawEventData).RoleName), RolePermissions = tostring(parse_json(RawEventData).RolePermissions), AssignedGroups = tostring(parse_json(RawEventData).AssignedGroups)
| project-reorder Timestamp, ActionType, AccountObjectId, RoleName, RolePermissions, AssignedGroups
```
## Sentinel
```
CloudAppEvents
| extend Workload = tostring(parse_json(RawEventData).Workload)
| where Workload contains "Defender"
| where ActionType endswith "Role"
| extend RoleName = tostring(parse_json(RawEventData).RoleName), RolePermissions = tostring(parse_json(RawEventData).RolePermissions), AssignedGroups = tostring(parse_json(RawEventData).AssignedGroups)
| project-reorder TimeGenerated, ActionType, AccountObjectId, RoleName, RolePermissions, AssignedGroups
```