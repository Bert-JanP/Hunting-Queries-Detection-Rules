# Triggers when a remote SBM connection has been found
----
### Defender XDR

```
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project-reorder Timestamp, DeviceName, RemoteIP
```
### Sentinel
```
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project-reorder TimeGenerated, DeviceName, RemoteIP
```



