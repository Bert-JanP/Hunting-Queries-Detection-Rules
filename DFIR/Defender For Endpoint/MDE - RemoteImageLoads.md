# Remote Image Loads

## Query Information

#### Description
This query can be used to summarize the remote image loads to a (potentially) compromised domain.

#### References
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/detect-compromised-rdp-sessions-with-microsoft-defender-for/ba-p/4201003

## Defender XDR
```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
let Threshold = 50; // Customizable
DeviceImageLoadEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where IsInitiatingProcessRemoteSession == 1
| summarize TotalEvents = count(), Commands = make_set(InitiatingProcessCommandLine) by InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, InitiatingProcessAccountUpn
| where TotalEvents <= Threshold
```
## Sentinel
```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
let Threshold = 50; // Customizable
DeviceImageLoadEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName == CompromisedDevice
| where IsInitiatingProcessRemoteSession == 1
| summarize TotalEvents = count(), Commands = make_set(InitiatingProcessCommandLine) by InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, InitiatingProcessAccountUpn
| where TotalEvents <= Threshold
```
