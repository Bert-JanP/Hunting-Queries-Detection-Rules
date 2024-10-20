# Latest Antivirus Scan Status

## Query Information

#### Description
This query lists the latest completed antivirus scan for each device. The query filters all devices that have performed a successful scan today. 

#### Risk
The Defender sensor is not working corretly and might not be able to idenfity suspicious behaviour.

#### References
- https://cloudbrothers.info/antivirus-scan-complete/

## Defender XDR
```KQL
DeviceEvents
| where ActionType == "AntivirusScanCompleted"
| summarize arg_max(Timestamp, *) by DeviceId
| extend ScanType = tostring(parse_json(AdditionalFields).ScanTypeIndex), 
    DaysAgo = datetime_diff('day', now(), Timestamp)
| project DeviceName, ActionType, ScanType, DaysAgo
// Filter only devices that have not performed a antivirus scan in the last day
| where DaysAgo > 0
| sort by DaysAgo
```
## Sentinel
```KQL
DeviceEvents
| where ActionType == "AntivirusScanCompleted"
| summarize arg_max(TimeGenerated, *) by DeviceId
| extend ScanType = tostring(parse_json(AdditionalFields).ScanTypeIndex), 
    DaysAgo = datetime_diff('day', now(), Timestamp)
| project DeviceName, ActionType, ScanType, DaysAgo
// Filter only devices that have not performed a antivirus scan in the last day
| where DaysAgo > 0
| sort by DaysAgo
```
