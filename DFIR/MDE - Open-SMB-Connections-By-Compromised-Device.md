# Show all successful SMB connections of a compromised device
----
## Defender XDR

```
let CompromisedDevice = "laptop1";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceNetworkEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
```
## Sentinel
```
let CompromisedDevice = "laptop1";
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceNetworkEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
```



