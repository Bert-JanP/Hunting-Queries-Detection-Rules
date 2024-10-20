# Custom Detection Deletion

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1070 | Indicator Removal | https://attack.mitre.org/techniques/T1070/ |

### Description
This query lists all the custom detections that have been deleted in Defender For XDR. The information is available in the *CloudAppEvents* table. This allows you to audit custom detection rule deletions and alert on deletion activities (from unknown users).

### Risk
An actor has gotten access to an account that is able to delete custom detections. By deleting custom detections they are able to stay undetected.

### References
- https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview
- https://kqlquery.com/posts/audit-defender-xdr/

## Defender XDR
```
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "DeleteCustomDetection"
| extend RuleName = tostring(parse_json(RawEventData).RuleName), Query = tostring(parse_json(RawEventData).Query), AlertDescription = parse_json(RawEventData).AlertDescription
| project-reorder AccountDisplayName, AccountId, RuleName, AlertDescription, Query
```
## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| where ActionType == "DeleteCustomDetection"
| extend RuleName = tostring(parse_json(RawEventData).RuleName), Query = tostring(parse_json(RawEventData).Query), AlertDescription = parse_json(RawEventData).AlertDescription
| project-reorder AccountDisplayName, AccountId, RuleName, AlertDescription, Query
```
