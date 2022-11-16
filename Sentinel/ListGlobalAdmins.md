# List all Global Admins in your tenant

### Sentinel

```
IdentityInfo
| where AssignedRoles contains "Global Admin"
| distinct AccountName, AccountDomain, AccountUPN, AccountSID
// If PIM is enabled for Global Admins the list shows only the Global Admins that have used PIM to gain the privileges.
```