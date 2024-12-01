# Find which devices have been accessed by a compromised device and which protocol was used to connect
----
## Defender XDR

```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityLogonEvents
| where Timestamp > (now() - SearchWindow)
| where DeviceName == CompromisedDevice
| summarize
     TotalDevicesAccessed = dcount(DestinationDeviceName),
     DevicesAccessed = make_set(DestinationDeviceName),
     ProtocolsUsed = make_set(Protocol)
     by DeviceName

```
## Sentinel
```
let CompromisedDevice = "laptop.contoso.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
IdentityLogonEvents
| where TimeGenerated > (now() - SearchWindow)
| where DeviceName == CompromisedDevice
| summarize
     TotalDevicesAccessed = dcount(DestinationDeviceName),
     DevicesAccessed = make_set(DestinationDeviceName),
     ProtocolsUsed = make_set(Protocol)
     by DeviceName
```



