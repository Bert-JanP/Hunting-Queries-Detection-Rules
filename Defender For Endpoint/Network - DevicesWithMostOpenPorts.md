# List the devices with the most open ports

## Query Information

#### Description
List the devices with the most open ports.

## Defender XDR
```KQL
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort < 5000 //Remove open TCP ports
| where LocalIP !="127.0.0.1" // Will generate a lot of false positives
| summarize TotalOpenPorts = dcount(LocalPort), OpenPortsList = make_set(LocalPort) by DeviceName
| sort by TotalOpenPorts
```

## Sentinel
```KQL
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort < 5000 //Remove open TCP ports
| where LocalIP !="127.0.0.1" // Will generate a lot of false positives
| summarize TotalOpenPorts = dcount(LocalPort), OpenPortsList = make_set(LocalPort) by DeviceName
| sort by TotalOpenPorts
```
