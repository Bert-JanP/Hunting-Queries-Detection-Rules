# List Antivirus Scan Activities

## Query Information

### Description
This query lists all manual (and playbook related) anvitius actions that are initiated and the related comments per device.

### References
- https://learn.microsoft.com/en-us/defender-endpoint/mdav-scan-best-practices

## Defender For Endpoint
```
CloudAppEvents
| where ActionType == "RunAntiVirusScan"
| extend DeviceName = tostring(parse_json(RawEventData).DeviceName), ActionComment = tostring(parse_json(RawEventData).ActionComment), ActionScope = tostring(parse_json(RawEventData).ActionScope)
| summarize TotalAntivirusScans = count(), ScanTypes = make_set(ActionScope), Comments = make_set(ActionComment) by DeviceName
```
## Sentinel
```
CloudAppEvents
| where ActionType == "RunAntiVirusScan"
| extend DeviceName = tostring(parse_json(RawEventData).DeviceName), ActionComment = tostring(parse_json(RawEventData).ActionComment), ActionScope = tostring(parse_json(RawEventData).ActionScope)
| summarize TotalAntivirusScans = count(), ScanTypes = make_set(ActionScope), Comments = make_set(ActionComment) by DeviceName
```