# List the devices with open remote service ports

## Query Information

#### Description
This query lists the devices with open remote service ports

The database ports defined in the query:
- 22: SSH
- 139: SMB
- 445: SMB
- 3389: RDP
- 5900: VNC
- 5985: WinRM v2
- 5986: WinRM

## Defender XDR
```KQL
let RemoteServices = dynamic([22, 139, 445, 3389, 5900, 5985, 5986]);
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (RemoteServices)
| summarize OpenPorts = make_set(LocalPort), TotalOpenRemoteServicesPorts = dcount(LocalPort) by DeviceName
| sort by TotalOpenRemoteServicesPorts
```

## Sentinel
```KQL
let RemoteServices = dynamic([22, 139, 445, 3389, 5900, 5985, 5986]);
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (RemoteServices)
| summarize OpenPorts = make_set(LocalPort), TotalOpenRemoteServicesPorts = dcount(LocalPort) by DeviceName
| sort by TotalOpenRemoteServicesPorts
```
