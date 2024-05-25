# Live Response File Collection

## Query Information

### Description
This query lists all the Getfile activities that have been executed. This includes listing the SHA256 hash of the collected file (when available).

### References
- https://kqlquery.com/posts/leveraging-live-response/
- https://learn.microsoft.com/en-us/defender-endpoint/live-response-command-examples
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function

## Defender For Endpoint
```
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "LiveResponseGetFile"
| extend FileName = tostring(parse_json(RawEventData).FileName), FileSHA256 = tostring(parse_json(RawEventData).FileSHA256)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId, SHA256 = FileSHA256
| invoke FileProfile(SHA256, 1000)
| project-reorder Timestamp, FileName, SHA256, InitiatedByAccountName, InitiatedByAccounttId, GlobalPrevalence, SignatureState
```
## Sentinel
```
CloudAppEvents
| where TimeGenerated > ago(30d)
| where ActionType == "LiveResponseGetFile"
| extend FileName = tostring(parse_json(RawEventData).FileName), FileSHA256 = tostring(parse_json(RawEventData).FileSHA256)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId, SHA256 = FileSHA256
| invoke FileProfile(SHA256, 1000)
| project-reorder TimeGenerated, FileName, SHA256, InitiatedByAccountName, InitiatedByAccounttId, GlobalPrevalence, SignatureState
```