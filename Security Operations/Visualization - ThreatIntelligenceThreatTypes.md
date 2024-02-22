# Threat Intelligence Threat Types

## Query Information

#### Description
The query can be used to visualize the different threat types you get from the MDTI connector to Sentinel. Some examples coult be botnet, phishing, MaliciousUrl or from a watchlist. This query can only be used in Sentinel. 

### References
- https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-threat-intelligence
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/threatintelligenceindicator


## Sentinel
```KQL
ThreatIntelligenceIndicator
| summarize Total = count() by ThreatType
| render piechart with(title="Threat Intelligence Threat Types") 
```