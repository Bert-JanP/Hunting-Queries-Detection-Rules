# Hunt for devices with the most SMB connections

## Query Information

#### Description
This hunting query lists all the devices and the unique connections they have made with a remote SMB port. Devices with a large number of connected SMB sessions can be interesting to investigate.

## Defender XDR

```KQL
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
// Collect the last event that a device has connected via SMB to a unique remote IP
| summarize arg_max(Timestamp, *) by DeviceId, RemoteIP
| summarize RemoteSMBUrls = make_set_if(RemoteUrl, isnotempty(RemoteUrl)), make_set_if(RemoteIP, isempty(RemoteUrl)), TotalConnections = dcount(RemoteIP) by DeviceName
| sort by TotalConnections
```

## Sentinel
```KQL
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
// Collect the last event that a device has connected via SMB to a unique remote IP
| summarize arg_max(TimeGenerated, *) by DeviceId, RemoteIP
| summarize RemoteSMBUrls = make_set_if(RemoteUrl, isnotempty(RemoteUrl)), make_set_if(RemoteIP, isempty(RemoteUrl)), TotalConnections = dcount(RemoteIP) by DeviceName
| sort by TotalConnections
```



