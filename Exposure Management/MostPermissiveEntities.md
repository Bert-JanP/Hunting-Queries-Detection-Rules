# Most Permissive Entities

## Query Information

#### Description
This query lists the top 100 entities that have the most permissions to perform a certain action on a resource. The query extracts the type of permissions, such as reader, contributor, owner and other (custom) roles. It is good practice to review the users with the most permissions, or put additional monitoring on their accounts. Because they are highly priviliged threat actors can perform a lot of actions once the account has been taken over.

#### References
- https://learn.microsoft.com/en-us/security-exposure-management/microsoft-security-exposure-management

## Defender XDR
```KQL
// Permission Statistics
ExposureGraphEdges
| where EdgeLabel == "has permissions to"
| extend Type = extract(@'"name":"(.*?)"', 1, tostring(EdgeProperties))
| where isnotempty(Type)
| summarize TotalPermissions = dcount(TargetNodeName), ResourceList = make_set(TargetNodeName, 100), PermissionTypeCount = dcount(Type), PermissionTypes = make_set(Type) by SourceNodeName
| sort by TotalPermissions, SourceNodeName
| project SourceNodeName, TotalPermissions, PermissionTypeCount, ResourceList, PermissionTypes
| top 100 by TotalPermissions
```
