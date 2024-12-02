# Large Number of Analytics Rules Deleted

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

#### Description
This query can be used to detect when a large number of Sentinel Analytics Rules is deleted in a short timeframe. This could be part of the detection lifecycle, but it could also have been done with malicious intent.

The query uses two input variables, Threshold and TimeFrame. The Threshold determines when the rule should alert, by default this is when more than 25 rules are deleted within the set TimeFrame. The IngestionTime variable is used to calculate from what moment the logs are included.

#### Risk
Someone deletes a large number of Sentinel Analytics rules to evade detections.

## Sentinel
```KQL
let Treshold = 100;
let TimeFrame = 24h;
let IngestionTime = 2*24h;
AzureActivity
| where ingestion_time() > ago(IngestionTime)
| where OperationNameValue =~ "MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE"
| where ActivityStatusValue =~ "Success"
| extend RuleId = tostring(parse_path(tostring(parse_json(Properties).entity)).Filename)
| join kind=leftouter (SentinelHealth | where TimeGenerated > ago(7d) | extend RuleId = tostring(ExtendedProperties.RuleId) | summarize arg_max(TimeGenerated, RecordId, SentinelResourceName) by RuleId) on $left.RuleId == $right.RuleId
| summarize TotalDeletedRules = dcount(RuleId), RuleNames = make_set(SentinelResourceName, 100), RuleIds = make_set(RuleId) by ResourceGroup, SubscriptionId, Caller, bin(TimeGenerated, TimeFrame)
| where TotalDeletedRules >= Treshold
```