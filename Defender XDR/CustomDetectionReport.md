# Custom Detection Report for Microsoft Defender

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070 | Indicator Removal | https://attack.mitre.org/techniques/T1070/ |

### Description
Reporting on detection rules, especially custom ones, is a key function for any decent Detection Engineering team. This query attempts to track all the (latest) actions performed around custom detections for Defender For Endpoint/XDR. That includes creation/deletion and modifications. The information is available in the *CloudAppEvents* table. The query can also be used to track already created rules (more below).

### How to track existing, already deployed rules?
The use case here is about *systematically* feeding a separate datastore (ex.: Splunk lookup, summary index) for later reporting on the rulset evolution. However, since most active rules will NOT generate a trace in the CloudAppEvents table until you modify/update them, one can leverage a quick mechanism supported by this query.

Follow the steps below to track *existing* rules:
- Update existing, active rules by adding a comment 'flag' within the rule's query so that it triggers an 'Edit' event. The comment should contain 'xxxFLAGxxx', something like: // xxxFLAGxxx
- Save the query without modifying any of its behavior (unless you have a legit change to make as well)
- Run the query provided below and check if the expected query is part of the results

While the query ignores all simple modifications (EditCustomDetection), it will consider the ones containing that flag in the rule's KQL query code. That might come in handy in case you want to ignore rules under development/testing. The query needs to be executed in a periodic interval, in my use case, it's executed via a Splunk scheduled search that leverages the Defender API integration.

### References
- https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender For Endpoint
```
search in(CloudAppEvents) 'Microsoft365Defender'
| where Timestamp > ago(180d)    // How far back to check
| where parse_json(RawEventData).Workload=='Microsoft365Defender'
// Track rule creation/mods/deletion
| where ActionType has_any ('CreateCustomDetection', 'EditCustomDetection', 'ChangeCustomDetectionRuleStatus', 'DeleteCustomDetection')
| extend RuleName = tostring((RawEventData).RuleName)
| extend RuleId = tostring((RawEventData).RuleId)
| extend Query = parse_json(RawEventData).Query
| extend AlertTitle = parse_json(RawEventData).AlertTitle
| extend Author = iff(ActionType=='CreateCustomDetection', parse_json(RawEventData).UserId, 'null')
| extend LastAuthor = parse_json(RawEventData).UserId
| extend AlertCategory = parse_json(RawEventData).AlertCategory
| extend AlertSeverity = parse_json(RawEventData).AlertSeverity
| extend MitreTechniques = parse_json(RawEventData).MitreTechniques
| extend RuleFrequency = parse_json(RawEventData).RuleFrequency
| extend CreationTime=iff(ActionType=='CreateCustomDetection', Timestamp, datetime(null))
| extend LastUpdateTime=iff(ActionType=='EditCustomDetection', Timestamp, datetime(null))
| extend IsEnabled = parse_json(RawEventData).IsEnabled
| extend IsEnabled = case(
  IsEnabled == false, 0,
  (IsEnabled == true) or ActionType=='CreateCustomDetection' or (ActionType=='EditCustomDetection' and Query has 'xxxFLAGxxx'), 1
  , int(null))
// Captures the latest states per rule name/id
| summarize arg_max(Timestamp, ActionType, CreationTime, LastUpdateTime, AlertTitle, Author, LastAuthor, 
  IsEnabled, AlertCategory, AlertSeverity, MitreTechniques, RuleFrequency, Query) 
  by RuleName, RuleId
//| project-away Query
```
## Sentinel
```
search in(CloudAppEvents) 'Microsoft365Defender'
| where TimeGenerated > ago(180d)    // How far back to check
| where parse_json(RawEventData).Workload=='Microsoft365Defender'
// Track rule creation/mods/deletion
| where ActionType has_any ('CreateCustomDetection', 'EditCustomDetection', 'ChangeCustomDetectionRuleStatus', 'DeleteCustomDetection')
| extend RuleName = tostring((RawEventData).RuleName)
| extend RuleId = tostring((RawEventData).RuleId)
| extend Query = parse_json(RawEventData).Query
| extend AlertTitle = parse_json(RawEventData).AlertTitle
| extend Author = iff(ActionType=='CreateCustomDetection', parse_json(RawEventData).UserId, 'null')
| extend LastAuthor = parse_json(RawEventData).UserId
| extend AlertCategory = parse_json(RawEventData).AlertCategory
| extend AlertSeverity = parse_json(RawEventData).AlertSeverity
| extend MitreTechniques = parse_json(RawEventData).MitreTechniques
| extend RuleFrequency = parse_json(RawEventData).RuleFrequency
| extend CreationTime=iff(ActionType=='CreateCustomDetection', Timestamp, datetime(null))
| extend LastUpdateTime=iff(ActionType=='EditCustomDetection', Timestamp, datetime(null))
| extend IsEnabled = parse_json(RawEventData).IsEnabled
| extend IsEnabled = case(
  IsEnabled == false, 0,
  (IsEnabled == true) or ActionType=='CreateCustomDetection' or (ActionType=='EditCustomDetection' and Query has 'xxxFLAGxxx'), 1
  , int(null))
// Captures the latest states per rule name/id
| summarize arg_max(Timestamp, ActionType, CreationTime, LastUpdateTime, AlertTitle, Author, LastAuthor, 
  IsEnabled, AlertCategory, AlertSeverity, MitreTechniques, RuleFrequency, Query) 
  by RuleName, RuleId
//| project-away Query
```
