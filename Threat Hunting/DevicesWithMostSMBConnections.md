# Hunt for devices with the most SMB connections
----
### Defender For Endpoint

```
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize arg_max(Timestamp, *) by DeviceId, RemoteIP
| summarize SMBSessions = make_set(RemoteUrl) by DeviceName
| extend TotalSMBConnections = array_length(SMBSessions)
| sort by TotalSMBConnections
```
### Sentinel
```
DeviceNetworkEvents
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize arg_max(TimeGenerated, *) by DeviceId, RemoteIP
| summarize SMBSessions = make_set(RemoteUrl) by DeviceName
| extend TotalSMBConnections = array_length(SMBSessions)
| sort by TotalSMBConnections
```



