# Total SMB Sessions Created by a suspicious device

## Query Information

#### Description
Total SMB Sessions Created by a suspicious device

## Defender XDR
```KQL
let TimeFrame = 24h; //Customizable h = hours, d = days
let SuspiciousDevices = dynamic(['server1.com', 'laptop1.com']);
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where RemotePort == 445
| where ActionType  == "ConnectionSuccess"
| where DeviceName in~ (SuspiciousDevices)
| summarize IPsAccessed = make_set(RemoteIP), TotalIPs = dcount(RemoteIP) by DeviceName
```

## Sentinel
```KQL
let TimeFrame = 24h; //Customizable h = hours, d = days
let SuspiciousDevices = dynamic(['server1.com', 'laptop1.com']);
DeviceNetworkEvents
| where TimeGenerated > ago(TimeFrame)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| where DeviceName in~ (SuspiciousDevices)
| summarize IPsAccessed = make_set(RemoteIP), TotalIPs = dcount(RemoteIP) by DeviceName
```
