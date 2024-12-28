# Custom Detection Disabled

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070 | Indicator Removal | https://attack.mitre.org/techniques/T1070/ |

### Description
This query lists all the custom detections that have been disabled in Defender For XDR. The information is available in the *CloudAppEvents* table. This allows you to audit custom detection rule status changed and alert on disable activities (from unknown users).

### Risk
An actor has gotten access to an account that is able to disabled custom detections. By disabling custom detections they are able to stay undetected.

### References
- https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "ChangeCustomDetectionRuleStatus"
| where RawEventData.IsEnabled == "false"
| extend RuleName = tostring(parse_json(RawEventData.RuleName)), Query = tostring(parse_json(RawEventData.Query)), Actor = tostring(parse_json(RawEventData.UserId)), IsEnabled = RawEventData.IsEnabled
| project-reorder Timestamp, Actor, IsEnabled, RuleName, Query
```

## Sentinel
```KQL
CloudAppEvents
| where ActionType == "ChangeCustomDetectionRuleStatus"
| where RawEventData.IsEnabled == "false"
| extend RuleName = tostring(parse_json(RawEventData.RuleName)), Query = tostring(parse_json(RawEventData.Query)), Actor = tostring(parse_json(RawEventData.UserId)), IsEnabled = RawEventData.IsEnabled
| project-reorder TimeGenerated, Actor, IsEnabled, RuleName, Query
```
