# Summary Rules - Entra Group Membership Report

## Query Information

#### Description
This summary rule focusses on the group memberships of users. The results of the summary rule can again be used to get insights into specific users, to for example see if their memberships increase or decrease overtime. These results can also serve as input for reporting on group memberships

**Recommended Schedule:** 24 hours.

**Recommended Delay:** 60 minutes.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/summary-rules
- https://kqlquery.com/posts/sentinel-summary-rules/

## Sentinel
```KQL
IdentityInfo
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand GroupMembership
| summarize TotalMemberships = dcount(tostring(GroupMembership)), MemberOf = make_set(tostring(GroupMembership), 1000) by AccountObjectId, AccountDisplayName, AccountUPN
| extend ReportDate = now()
```
