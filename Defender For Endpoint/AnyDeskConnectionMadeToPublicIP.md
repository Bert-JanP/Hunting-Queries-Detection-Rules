# Detect when AnyDesk makes a remote connection

### Defender For Endpoint

```
DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| where LocalIPType == "Private"
| where RemoteIPType == "Public"
| where RemoteUrl != "boot.net.anydesk.com" // Initial AnyDesk Connection when booted.
| project
     Timestamp,
     DeviceId,
     InitiatingProcessAccountName,
     ActionType,
     RemoteIP,
     RemotePort,
     RemoteUrl
```
### Sentinel
```
DeviceNetworkEvents
| where InitiatingProcessFileName == "AnyDesk.exe"
| where LocalIPType == "Private"
| where RemoteIPType == "Public"
| where RemoteUrl != "boot.net.anydesk.com" // Initial AnyDesk Connection when booted.
| project
     TimeGenerated,
     DeviceId,
     InitiatingProcessAccountName,
     ActionType,
     RemoteIP,
     RemotePort,
     RemoteUrl
```



