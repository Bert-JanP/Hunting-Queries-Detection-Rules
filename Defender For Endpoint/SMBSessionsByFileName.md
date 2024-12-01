# Total SMB Sessions Created by FileName

## Query Information

#### Description
Total SMB Sessions Created by FileName

## Defender XDR
```KQL
let TimeFrame = 24h; //Customizable h = hours, d = days
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where RemotePort == 445
| where InitiatingProcessFileName <> "Microsoft.Tri.Sensor.exe" // MDI Sensor
| where InitiatingProcessFileName <> "sensendr.exe" // MDE Device Discovery
| summarize dcount(RemoteIP) by InitiatingProcessFileName, InitiatingProcessFolderPath
```

## Sentinel
```KQL
let TimeFrame = 24h; //Customizable h = hours, d = days
DeviceNetworkEvents
| where TimeGenerated > ago(TimeFrame)
| where RemotePort == 445
| where InitiatingProcessFileName <> "Microsoft.Tri.Sensor.exe" // MDI Sensor
| where InitiatingProcessFileName <> "sensendr.exe" // MDE Device Discovery
| summarize dcount(RemoteIP) by InitiatingProcessFileName, InitiatingProcessFolderPath
```
