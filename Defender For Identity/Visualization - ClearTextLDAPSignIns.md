# Devices that initiate the most clear text LDAP authentications 

## Query Information

#### Description
This query visualises the top 100 Devices that initiate the most clear text LDAP authentications. You preferably want to use an encrypted form of LDAP instead of cleartext.

## Defender XDR

```
IdentityLogonEvents
| where LogonType == 'LDAP cleartext'
| where ActionType == 'LogonSuccess'
| distinct DeviceName, AccountUpn
| summarize TotalUniqueClearTextLDAPAuthentications = count() by DeviceName
| top 100 by TotalUniqueClearTextLDAPAuthentications
| render columnchart with (title="Top 100 Devices with the most Clear Text LDAP sign ins")
```
## Sentinel
```
IdentityLogonEvents
| where LogonType == 'LDAP cleartext'
| where ActionType == 'LogonSuccess'
| distinct DeviceName, AccountUpn
| summarize TotalUniqueClearTextLDAPAuthentications = count() by DeviceName
| top 100 by TotalUniqueClearTextLDAPAuthentications
| render columnchart with (title="Top 100 Devices with the most Clear Text LDAP sign ins")
```



