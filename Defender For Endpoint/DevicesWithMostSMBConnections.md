# Hunt for devices with the most SMB connections

## Query Information

#### Description
This hunting query lists all the devices and the unique connections they have made with a remote SMB port. Devices with a large number of connected SMB sessions can be interesting to investigate.

## Defender XDR

```
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
// Collect the last event that a device has connected via SMB to a unique remote IP
| summarize arg_max(Timestamp, *) by DeviceId, RemoteIP
| summarize SMBSessions = make_set(RemoteUrl) by DeviceName
| extend TotalSMBConnections = array_length(SMBSessions)
| sort by TotalSMBConnections
```
## Sentinel
```
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
// Collect the last event that a device has connected via SMB to a unique remote IP
| summarize arg_max(TimeGenerated, *) by DeviceId, RemoteIP
| summarize SMBSessions = make_set(RemoteUrl) by DeviceName
| extend TotalSMBConnections = array_length(SMBSessions)
| sort by TotalSMBConnections
```



