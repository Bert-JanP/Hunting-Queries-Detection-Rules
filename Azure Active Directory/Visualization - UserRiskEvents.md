# User Risk Visualization last 90 days

## Query Information

#### Description
This visualization list the User Risk Events that have triggered in the last 90 days. The count per day is classified by the RiskEventType, those can amongs others be:
- AnonymizedIPAddress
- NewCountry
- UnfamliliarFeatures

This visualization can give insight in the amount of risky events that have happened. 

#### References
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aaduserriskevents

## Sentinel
```
AADUserRiskEvents
| where TimeGenerated > ago(90d)
| summarize count() by bin(TimeGenerated, 1d), RiskEventType
| render columnchart
```