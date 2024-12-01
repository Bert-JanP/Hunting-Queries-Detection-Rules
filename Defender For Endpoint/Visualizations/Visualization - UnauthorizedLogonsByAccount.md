# Unauthorized Logon actions by Domain and Account

## Defender XDR

```
DeviceLogonEvents
| where isnotempty(FailureReason)
| where FailureReason == "UnauthorizedLogonType"
| summarize count() by AccountDomain, AccountName
| sort by count_
| render columnchart with(title="Unauthorized Logon by Domain and Account")
```
## Sentinel
```
DeviceLogonEvents
| where isnotempty(FailureReason)
| where FailureReason == "UnauthorizedLogonType"
| summarize count() by AccountDomain, AccountName
| sort by count_
| render columnchart with(title="Unauthorized Logon by Domain and Account")
```



