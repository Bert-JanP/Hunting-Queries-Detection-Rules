# Logon Failure Reasons

## Defender XDR

```
DeviceLogonEvents
| where isnotempty(FailureReason)
| summarize count() by FailureReason
| render piechart with (title="Logon Failure Reasons")
```
## Sentinel
```
DeviceLogonEvents
| where isnotempty(FailureReason)
| summarize count() by FailureReason
| render piechart with (title="Logon Failure Reasons")
```



