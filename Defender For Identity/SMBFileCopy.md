# Detect SMB File Copies

### Defender For Endpoint

```
let WhitelistedAccounts = dynamic(['account1', 'account2']);
IdentityDirectoryEvents
| where ActionType == 'SMB file copy'
| where not(AccountName has_any (WhitelistedAccounts))
| extend SMBFileCopyCount = parse_json(AdditionalFields).Count
| extend FilePath = parse_json(AdditionalFields).FilePath
| extend FileName = parse_json(AdditionalFields).FileName
| project-rename SourceDeviceName = DeviceName
| project-reorder
     Timestamp,
     ActionType,
     SourceDeviceName,
     DestinationDeviceName,
     FilePath,
     FileName,
     SMBFileCopyCount
```
### Sentinel
```
let WhitelistedAccounts = dynamic(['account1', 'account2']);
IdentityDirectoryEvents
| where ActionType == 'SMB file copy'
| where not(AccountName has_any (WhitelistedAccounts))
| extend SMBFileCopyCount = parse_json(AdditionalFields).Count
| extend FilePath = parse_json(AdditionalFields).FilePath
| extend FileName = parse_json(AdditionalFields).FileName
| project-rename SourceDeviceName = DeviceName
| project-reorder
     TimeGenerated,
     ActionType,
     SourceDeviceName,
     DestinationDeviceName,
     FilePath,
     FileName,
     SMBFileCopyCount
```



