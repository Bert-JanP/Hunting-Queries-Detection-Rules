# Detect SMB File Copies

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares|https://attack.mitre.org/techniques/T1021/002|

#### Description
Adversaries can use SMB to upload files to remote shares or to interact with files on those shares. A common technique is to upload malcious to remote host. This query detects all SMB file copies. In order to run the query effectively add the benign accounts the the whitelist.

A false positive would be a aministrator that would perform legitimate SMB file copies. 

#### Risk
A actor uses a SMB file copy to distrubute malware in your environment. 

## Defender XDR
```KQL
let WhitelistedAccounts = dynamic(['account1', 'account2']);
IdentityDirectoryEvents
| where ActionType == 'SMB file copy'
| where not(AccountName has_any (WhitelistedAccounts))
| extend 
     SMBFileCopyCount = parse_json(AdditionalFields).Count,
     FilePath = parse_json(AdditionalFields).FilePath,
     FileName = parse_json(AdditionalFields).FileName
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

## Sentinel 
```KQL
let WhitelistedAccounts = dynamic(['account1', 'account2']);
IdentityDirectoryEvents
| where ActionType == 'SMB file copy'
| where not(AccountName has_any (WhitelistedAccounts))
| extend 
     SMBFileCopyCount = parse_json(AdditionalFields).Count,
     FilePath = parse_json(AdditionalFields).FilePath,
     FileName = parse_json(AdditionalFields).FileName
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



