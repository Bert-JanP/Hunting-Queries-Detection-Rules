# Sign Ins by UserAgent

This query can be used to detect rare UserAgents that are used to sign into your tenant. Those rare UserAgents can be used for malicious acces into your tenant.

### Sentinel
```
SigninLogs
| summarize count() by UserAgent
| sort by count_
```
