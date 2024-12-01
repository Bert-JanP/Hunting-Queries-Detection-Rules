# Devices with the most SMB connections

## Query Information

#### Description
List all devices with the amount of SMB sessions they have.

## Defender XDR
```KQL
let TimeFrame = 24h; //Customizable h = hours, d = days
let AllDomainControllers =
     DeviceNetworkEvents
     | where LocalPort == 88
     | where LocalIPType == "FourToSixMapping"
     | summarize make_set(DeviceId);
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where RemotePort == 445
| where not(DeviceId in (AllDomainControllers)) // THis is to reduce FP because of e.g. MDI, if you do not have MDI do not use this filter.
| summarize TotalRemoteConnections = dcount(RemoteIP) by DeviceName
| sort by TotalRemoteConnections
```

## Sentinel
```KQL
let TimeFrame = 24h; //Customizable h = hours, d = days
let AllDomainControllers =
     DeviceNetworkEvents
     | where LocalPort == 88
     | where LocalIPType == "FourToSixMapping"
     | summarize make_set(DeviceId);
DeviceNetworkEvents
| where TimeGenerated > ago(TimeFrame)
| where RemotePort == 445
| where not(DeviceId in (AllDomainControllers)) // This is to reduce FP because of e.g. MDI, if you do not have MDI do not use this filter.
| summarize TotalRemoteConnections = dcount(RemoteIP) by DeviceName
| sort by TotalRemoteConnections
```
