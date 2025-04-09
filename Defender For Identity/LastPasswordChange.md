# Last Password Change User

## Query Information

#### Description
This query lists the last PasswordChangeTime based on Active Directory logs. In case you asked a user to perform a password reset, you can confirm using this query if it was actually performed.

## Defender XDR
```KQL
let UPN = "test@kqlquery.com";
IdentityDirectoryEvents
| where ActionType == "Account Password changed"
| where AccountUpn =~ UPN
| summarize arg_max(Timestamp, *) by AccountUpn
| project PasswordChangeTime = Timestamp, Application, AccountDomain, AccountSid, AccountUpn
```

## Sentinel
```KQL
let UPN = "test@kqlquery.com";
IdentityDirectoryEvents
| where ActionType == "Account Password changed"
| where AccountUpn =~ UPN
| summarize arg_max(TimeGenerated, *) by AccountUpn
| project PasswordChangeTime = TimeGenerated, Application, AccountDomain, AccountSid, AccountUpn
```
