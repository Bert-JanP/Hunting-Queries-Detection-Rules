# Summary Rules - Entra Assigned Roles Report

## Query Information

#### Description
This summary rule focusses on the assigned roles of users. The results of the summary rule can again be used to get insights into specific users, to for example see if their roles increase or decrease overtime. These results can also serve as input for reporting on role assignments.

**Recommended Schedule:** 24 hours.

**Recommended Delay:** 60 minutes.
#### References
- https://learn.microsoft.com/en-us/azure/sentinel/summary-rules
- https://kqlquery.com/posts/sentinel-summary-rules/

## Sentinel
```KQL
IdentityInfo
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand AssignedRoles
| where isnotempty(AssignedRoles)
| summarize TotalRoles = dcount(tostring(AssignedRoles)), Roles = make_set(tostring(AssignedRoles), 100) by AccountObjectId, AccountDisplayName, AccountUPN
| extend ReportDate = now()
```
