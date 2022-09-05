# Devices that initiate the most clear text LDAP authentications 

### Defender For Endpoint

```
IdentityLogonEvents
| where LogonType == 'LDAP cleartext'
| where ActionType == 'LogonSuccess'
| distinct DeviceName, AccountUpn
| summarize TotalUniqueClearTextLDAPAuthentications = count() by DeviceName
| top 100 by TotalUniqueClearTextLDAPAuthentications
| render columnchart with (title="Top 100 Devices with the most Clear Text LDAP sign ins")
```
### Sentinel
```
IdentityLogonEvents
| where LogonType == 'LDAP cleartext'
| where ActionType == 'LogonSuccess'
| distinct DeviceName, AccountUpn
| summarize TotalUniqueClearTextLDAPAuthentications = count() by DeviceName
| top 100 by TotalUniqueClearTextLDAPAuthentications
| render columnchart with (title="Top 100 Devices with the most Clear Text LDAP sign ins")
```



