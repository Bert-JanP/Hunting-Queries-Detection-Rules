# Group Membership Report

## Query Information

#### Description
This query can be used to draw an report of the Entra ID group memberships of all users.

Note: if a users has more than 1000 memberships remove the 1000 limitation in the make_set to display all groupnames.

## Defender XDR
```KQL
let TimeFrame = 30d;
IdentityInfo
| where Timestamp > ago(TimeFrame)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand GroupMembership
| summarize TotalMemberships = dcount(tostring(GroupMembership)), MemberOf = make_set(tostring(GroupMembership), 1000) by AccountObjectId, AccountDisplayName, AccountUPN
| extend ReportDate = now()
```
## Sentinel
```KQL
let TimeFrame = 30d;
IdentityInfo
| where TimeGenerated > ago(TimeFrame)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand GroupMembership
| summarize TotalMemberships = dcount(tostring(GroupMembership)), MemberOf = make_set(tostring(GroupMembership), 1000) by AccountObjectId, AccountDisplayName, AccountUPN
| extend ReportDate = now()
```