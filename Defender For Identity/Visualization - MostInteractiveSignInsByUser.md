# Top 100 users that have the most interactive sign ins


### Defender For Endpoint

```
IdentityLogonEvents
| where LogonType == 'Interactive'
| where isempty(FailureReason)
| distinct AccountUpn, DeviceName
| summarize TotalUniqueInteractiveSignIns = count() by AccountUpn
| top 100 by TotalUniqueInteractiveSignIns
| render columnchart with (title="Top 100 users that have the most interactive sign ins")
```
### Sentinel
```
IdentityLogonEvents
| where LogonType == 'Interactive'
| where isempty(FailureReason)
| distinct AccountUpn, DeviceName
| summarize TotalUniqueInteractiveSignIns = count() by AccountUpn
| top 100 by TotalUniqueInteractiveSignIns
| render columnchart with (title="Top 100 users that have the most interactive sign ins")
```



