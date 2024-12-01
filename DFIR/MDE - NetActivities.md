# List all net(1).exe activities on a host
----
## Defender XDR

```
let CompromisedDevice = "azurewin2022";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
//| where DeviceName == CompromisedDevice
| where Timestamp > ago(SearchWindow)
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS",
    ProcessCommandLine has "group", "GROUP",
    ProcessCommandLine has "user", "USER",
    ProcessCommandLine has "localgroup", "LOCALGROUP",
    "Other")
| where NetActionType != "Other"
| project-reorder Timestamp, ProcessCommandLine
| sort by Timestamp
```
## Sentinel
```
let CompromisedDevice = "azurewin2022";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceProcessEvents
//| where DeviceName == CompromisedDevice
| where TimeGenerated > ago(SearchWindow)
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS",
    ProcessCommandLine has "group", "GROUP",
    ProcessCommandLine has "user", "USER",
    ProcessCommandLine has "localgroup", "LOCALGROUP",
    "Other")
| where NetActionType != "Other"
| project-reorder TimeGenerated, ProcessCommandLine
| sort by TimeGenerated
```



