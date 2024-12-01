# Visualize the Threat Intelligence Indicators by day for the last 30 days

## Query Information

#### Description
This query visualizes the amount of IOCs that have triggerd each day for the last 30 days in a timechart. This could indicate spikes in malicious activities by users or give intsights in the value of Threat Intelligence feeds. 

## Sentinel
```KQL
ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| extend IOC = iff(isnotempty(DomainName), DomainName, 
iff(isnotempty(NetworkIP), NetworkIP, iff(isnotempty(Url), Url, "No IOC defined")))
| summarize count() by bin(TimeGenerated, 1d), IOC
| render columnchart with (kind=stacked, title="Threat Intelligence Indicators triggered each day")
```



