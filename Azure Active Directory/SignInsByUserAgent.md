# Sign Ins by UserAgent

## Query Information

#### Description
This query can be used to detect rare UserAgents that are used to sign into your tenant. Those rare UserAgents can be used for malicious acces into your tenant.

The query can be extended by filtering on succesful and failed sign ins. 

## Sentinel
```
SigninLogs
| summarize count() by UserAgent
| sort by count_
```
