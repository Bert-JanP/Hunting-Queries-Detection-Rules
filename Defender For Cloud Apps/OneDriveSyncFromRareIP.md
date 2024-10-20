# OneDrive Sync From Rare IP

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1530 | Data from Cloud Storage | https://attack.mitre.org/techniques/T1530/ |

#### Description
This query combines the CloudAppEvents table and the SignInLogs from Entra ID to hunt for OneDrive Sync activities from a rare IP address. The variables should be set based on your needs.

False Positive Consideration:
- Big file Uploads from new IPs

#### Risk
Adversaries may sync a OneDrive to their device to exfiltrate the data.

## Defender XDR
```KQL
let Threshold = 1500; // Change depeding on org needs.
let TimeFrame = 10m;
let EntraUserIPInfo = AADSignInEventsBeta
    // Filter only successful logins
    | where ErrorCode == 0
    | summarize IPEventCount = count() by IPAddress, AccountObjectId
    | where IPEventCount < 500;
CloudAppEvents
| where ActionType == "FileSyncUploadedFull"
| extend BaseFolder = split(parse_url(ObjectName).Path, "/")[3]
| summarize TotalEvents = count(), BaseFolders = make_set(BaseFolder, 25) by bin(TimeGenerated, TimeFrame), AccountId, AccountDisplayName, DeviceType, OSPlatform, IPAddress
| where TotalEvents >= Threshold
// Filter if the activity happens in combination with a rare IP
| join kind=inner EntraUserIPInfo on $left.AccountId == $right.AccountObjectId
| project TimeGenerated, TotalEvents, BaseFolders,  AccountId, AccountDisplayName, DeviceType, OSPlatform, IPAddress, IPEventCount
```
## Sentinel
```KQL
let Threshold = 1500; // Change depeding on org needs.
let TimeFrame = 10m;
let EntraUserIPInfo = SigninLogs
    // Filter only successful logins
    | where ResultType == 0
    | summarize IPEventCount = count() by IPAddress, UserId
    | where IPEventCount < 500;
CloudAppEvents
| where ActionType == "FileSyncUploadedFull"
| extend BaseFolder = split(parse_url(ObjectName).Path, "/")[3]
| summarize TotalEvents = count(), BaseFolders = make_set(BaseFolder, 25) by bin(TimeGenerated, TimeFrame), AccountId, AccountDisplayName, DeviceType, OSPlatform, IPAddress
| where TotalEvents >= Threshold
// Filter if the activity happens in combination with a rare IP
| join kind=inner EntraUserIPInfo on $left.AccountId == $right.UserId
| project TimeGenerated, TotalEvents, BaseFolders,  AccountId, AccountDisplayName, DeviceType, OSPlatform, IPAddress, IPEventCount
```
