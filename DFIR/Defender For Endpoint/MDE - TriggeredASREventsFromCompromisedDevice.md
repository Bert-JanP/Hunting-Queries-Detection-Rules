# Find all the ASR events that have triggered from a compromised device

## Defender XDR

```
let CompromisedDevice = "laptop1";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType startswith "ASR"
| project
     Timestamp,
     ActionType,
     FileName,
     FolderPath,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     AccountDomain,
     AccountName
```
## Sentinel
```
let CompromisedDevice = "laptop1";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where ActionType startswith "ASR"
| project
     TimeGenerated,
     ActionType,
     FileName,
     FolderPath,
     ProcessCommandLine,
     InitiatingProcessCommandLine,
     AccountDomain,
     AccountName
```



