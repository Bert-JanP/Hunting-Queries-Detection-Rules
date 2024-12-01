# List all Global Admins in your tenant

## Query Information

#### Description
This query lists all accounts that have the Global Admin role assigned to their account. If you have enabled PIM, then only users that have pimmed to Global Admin in the search period will be shown. 

#### References
- https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator

## Sentinel
```KQL
IdentityInfo
| where AssignedRoles contains "Global Admin"
| distinct AccountName, AccountDomain, AccountUPN, AccountSID
// If PIM is enabled for Global Admins the list shows only the Global Admins that have used PIM to gain the privileges.
```
