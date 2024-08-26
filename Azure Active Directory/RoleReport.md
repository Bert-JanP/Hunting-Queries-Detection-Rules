# Role Report

## Query Information

#### Description
This query can be used to draw an report of the Entra ID role memberships for all users.

## Defender XDR
```KQL
let TimeFrame = 30d;
IdentityInfo
| where Timestamp > ago(TimeFrame)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand AssignedRoles
| where isnotempty(AssignedRoles)
| summarize TotalRoles = dcount(tostring(AssignedRoles)), MemberOf = make_set(tostring(AssignedRoles), 1000) by AccountObjectId, AccountDisplayName, AccountUPN
| extend ReportDate = now()
| sort by TotalRoles desc  
```
## Sentinel
```KQL
let TimeFrame = 30d;
IdentityInfo
| where TimeGenerated > ago(TimeFrame)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand AssignedRoles
| where isnotempty(AssignedRoles)
| summarize TotalRoles = dcount(tostring(AssignedRoles)), MemberOf = make_set(tostring(AssignedRoles), 1000) by AccountObjectId, AccountDisplayName, AccountUPN
| extend ReportDate = now()
| sort by TotalRoles desc
```