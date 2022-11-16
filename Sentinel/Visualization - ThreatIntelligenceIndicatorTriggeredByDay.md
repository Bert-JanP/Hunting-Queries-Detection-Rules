# Visualize the Threat Intelligence Indicators by day for the last 30 days

### Sentinel
```
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, 
iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url), Url, "No IOC defined")))
| summarize count() by bin(TimeGenerated, 1d), IOC
| render columnchart with (kind=stacked, title="Threat Intelligence Indicators triggered each day")
```



