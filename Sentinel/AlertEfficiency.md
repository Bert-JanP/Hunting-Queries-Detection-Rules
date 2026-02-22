# Alert Efficiency

## Query Information

#### Description
The rule below can be used to calculate the efficiency of custom detection rules in your environment. The line ```| where AlertName startswith "[DxBP]"``` should be replaced with the prefix of your custom detection rules or should be removed completely to include build in rules as well.

## Sentinel
```KQL
let TimeRange = 365d;
SecurityIncident
| where TimeGenerated > ago(TimeRange)
// Collect last argumtent of incident
| summarize arg_max(TimeGenerated, Title, AlertIds, Severity, Classification) by IncidentNumber
// Only filter on closed incidents.
| where isnotempty(Classification)
| mv-expand AlertIds to typeof(string)
| join kind=inner ( SecurityAlert 
    // Filter Custom Detection Prefix Tenant
    | where AlertName startswith "[DxBP]"
    | where TimeGenerated > ago(TimeRange) 
    | summarize arg_max(TimeGenerated, SystemAlertId, AlertName) by SystemAlertId) 
    on $left.AlertIds == $right.SystemAlertId
// Calculate statistics
| summarize
    // Total unique alerts raised for this detection (distinct SystemAlertId).
    // Use this as the main denominator when each alert has a single classification.
    TotalAlertsTriggered = dcount(SystemAlertId),
    // Number of alerts whose outcome wasn’t concluded.
    // High values indicate investigation load and potential workflow gaps.
    TotalUndetermined    = countif(Classification == "Undetermined"),
    // Number of alerts correctly identified as benign (expected/allowed behavior).
    // Useful to quantify “known good but noisy” detections that still trigger.
    TotalBenignPositive  = countif(Classification == "BenignPositive"),
    // Number of alerts confirmed as genuinely malicious.
    // This is the primary “value delivered” signal for the detection.
    TotalTruePositive    = countif(Classification == "TruePositive"),
    // Number of alerts that were investigated and proven not malicious.
    // This directly reflects analyst toil and detection noise.
    TotalFalsePositive   = countif(Classification == "FalsePositive")
  by AlertName
| extend
    // Share of all triggered alerts that were true positives.
    // Higher is better; indicates yield of useful alerts.
    PctTruePositive      = round(100.0 * todouble(TotalTruePositive)
                                 / iif(TotalAlertsTriggered==0, real(null), todouble(TotalAlertsTriggered)), 2),
    // Share of all triggered alerts that were false positives.
    // Lower is better; indicates noise and wasted investigation effort.
    PctFalsePositive     = round(100.0 * todouble(TotalFalsePositive)
                                 / iif(TotalAlertsTriggered==0, real(null), todouble(TotalAlertsTriggered)), 2),
    // Share of all triggered alerts that were benign positives.
    // Helps separate “expected but noisy” from truly incorrect detections.
    PctBenignPositive    = round(100.0 * todouble(TotalBenignPositive)
                                 / iif(TotalAlertsTriggered==0, real(null), todouble(TotalAlertsTriggered)), 2),
    // Share of all triggered alerts that remain undetermined.
    // Indicates backlog or ambiguity in triage/investigation process.
    PctUndetermined      = round(100.0 * todouble(TotalUndetermined)
                                 / iif(TotalAlertsTriggered==0, real(null), todouble(TotalAlertsTriggered)), 2),
    // Precision (a.k.a. Positive Predictive Value): of all alerts judged suspicious (TP+FP),
    // what fraction were truly malicious? Higher is better (less analyst toil).
    PrecisionPct         = round(100.0 * todouble(TotalTruePositive)
                                 / iif(TotalTruePositive + TotalFalsePositive == 0,
                                       real(null),
                                       todouble(TotalTruePositive + TotalFalsePositive)), 2),
    // False Discovery Rate: complement of precision over the same TP+FP set.
    // Lower is better; directly represents the share of erroneous detections.
    FalseDiscoveryRatePct= round(100.0 * todouble(TotalFalsePositive)
                                 / iif(TotalTruePositive + TotalFalsePositive == 0,
                                       real(null),
                                       todouble(TotalTruePositive + TotalFalsePositive)), 2)
// Sort to surface the most effective detections first: high precision, then high TP share.
| sort by PrecisionPct desc, PctTruePositive desc
```
