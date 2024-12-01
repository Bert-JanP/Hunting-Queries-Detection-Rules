# Triggers when a remote public SBM connection has been found

## Query Information

#### Description
Triggers when a remote public SBM connection has been found

## Defender XDR
```KQL
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project-reorder Timestamp, DeviceName, RemoteIP
```

## Sentinel
```KQL
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project-reorder TimeGenerated, DeviceName, RemoteIP
```
