# Analytics Rules Efficiency 

## Query Information

#### Description
This query is aimed to improve the false positive ratio you have in Sentinel. The query list all analytics rules that have triggered the most in the selected TimeRange. These analytics rules can either be enabled ones from a template, or custom created detections. For each analytics rule the following stats are collected: 
- TotalIncidentsTriggered
- TotalUndetermined
- TotalBenignPositive
- TotalTruePositive
- TotalFalsePositive

Those stats can indicate the efficiency of a detection rule. Rules that trigger a lot of false positives or benign positives may need to be tweaked. Rules that trigger a lot of undetermined classifications may be worth adding more context to the alert or change the description or tasks to improve the reponse on this incident, to be able to classify it next time.

Also take a look at the Analytics Efficienty Workbook that is avialable on the Analytics page in Sentinel. 

## Sentinel
```KQL
let TimeRange = 30d;
SecurityIncident
| where TimeGenerated > ago(TimeRange)
// Collect last argumtent of incident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
// Filter only on Analytics rules in Sentinel
| where RelatedAnalyticRuleIds != "[]"
// Only filter on closed incidents.
| where isnotempty(Classification)
| summarize
     TotalIncidentsTriggered = count(),
     TotalUndetermined = countif(Classification == "Undetermined"),
     TotalBenignPositive = countif(Classification == "BenignPositive"),
     TotalTruePositive = countif(Classification == "TruePositive"),
     TotalFalsePositive = countif(Classification == "FalsePositive")
     by tostring(RelatedAnalyticRuleIds), Title
// Sort by incidents that do not trigger malicious activities
| sort by TotalFalsePositive, TotalIncidentsTriggered
```
