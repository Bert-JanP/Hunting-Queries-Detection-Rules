# Visualize the Threat Intelligence Indicators last 30 days

## Query Information

#### Description
This query visualizes the IOCs that have triggerd in the last 30 days. That can for example be Domains, IPs or URLs. THe resuls are rendered in a Piechart. 

## Sentinel
```KQL
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url),Url, "No IOC defined")))
| summarize count() by IOC
| render piechart with (title="Threat Intelligence Indicators by IOC last month")
```



