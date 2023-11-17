# Guest user with AD roles

## Query Information

#### Description
This query can be used to display all Guest users in the tenant who have Azure Active Directory roles. Guest users by default have different rights than normal users, at the time these Guest users get additional roles those permissions change. Therefore, the least privilege principle should be applied to Guest (and all other) users, so that these Guest users cannot access sensitive information. 

#### Risk
A Guest user has High privliges and could perform more actions then needed. 

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
- https://learn.microsoft.com/en-us/azure/active-directory/external-identities/b2b-quickstart-add-guest-users-portal
- https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-external-users


## Sentinel
```KQL
IdentityInfo
| where UserType == "Guest"
// Collect the most recent information for each Guest user
| summarize arg_max(TimeGenerated, *) by AccountUPN
// Only show Guests that have roles in your tentant
| where array_length(AssignedRoles) > 0
| project AccountUPN, AssignedRoles, IsAccountEnabled
```
