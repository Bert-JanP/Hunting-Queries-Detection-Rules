# Visualize the Threat Intelligence Indicators last 30 days

### Sentinel
```
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, 
iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url),Url, "No IOC defined")))
| summarize count() by IOC
| render piechart with (title="Threat Intelligence Indicators by IOC last month")
```



