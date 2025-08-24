# File From Host Collected

## Query Information

### Description
This query lists all the file downloads from an onboarded EDR device. The query lists the two file collection methods:
1. LiveResponseGetFile: Files collected through the *getfile* command in Live Response
2: DownloadFile: Files collected though the XDR portal by using the download file feature.

### References
- https://kqlquery.com/posts/audit-defender-xdr/
- https://learn.microsoft.com/en-us/defender-endpoint/investigate-files
- https://learn.microsoft.com/en-us/defender-endpoint/live-response-command-examples#getfile

## Defender XDR
```KQL
CloudAppEvents
| where ActionType in ('LiveResponseGetFile', 'DownloadFile')
| extend FileName = tostring(RawEventData.FileName), FileSHA256 = tostring(RawEventData.FileSHA256), FileSize = tostring(RawEventData.FileSize)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder Timestamp, InitiatedByAccountName, InitiatedByAccounttId, IPAddress, FileName, FileSHA256, FileSize
```

## Sentinel
```KQL
CloudAppEvents
| where ActionType in ('LiveResponseGetFile', 'DownloadFile')
| extend FileName = tostring(RawEventData.FileName), FileSHA256 = tostring(RawEventData.FileSHA256), FileSize = tostring(RawEventData.FileSize)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder TimeGenerated, InitiatedByAccountName, InitiatedByAccounttId, IPAddress, FileName, FileSHA256, FileSize
```
