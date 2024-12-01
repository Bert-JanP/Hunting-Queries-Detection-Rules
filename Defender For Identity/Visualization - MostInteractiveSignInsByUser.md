# Top 100 users that have the most interactive sign ins

## Query Information

#### Description
Visualize the top 100 users that have performed the most interactive sign ins.

### Defender XDR
```KQL
IdentityLogonEvents
| where LogonType == 'Interactive'
| where isempty(FailureReason)
| distinct AccountUpn, DeviceName
| summarize TotalUniqueInteractiveSignIns = count() by AccountUpn
| top 100 by TotalUniqueInteractiveSignIns
| render columnchart with (title="Top 100 users that have the most interactive sign ins")
```

### Sentinel
```KQL
IdentityLogonEvents
| where LogonType == 'Interactive'
| where isempty(FailureReason)
| distinct AccountUpn, DeviceName
| summarize TotalUniqueInteractiveSignIns = count() by AccountUpn
| top 100 by TotalUniqueInteractiveSignIns
| render columnchart with (title="Top 100 users that have the most interactive sign ins")
```



