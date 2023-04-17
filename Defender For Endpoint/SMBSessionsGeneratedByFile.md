# Total SMB Sessions Created by FileName

### Defender For Endpoint
```
let TimeFrame = 24h; //Customizable h = hours, d = days
DeviceNetworkEvents
| where Timestamp > ago(TimeFrame)
| where RemotePort == 445
| where InitiatingProcessFileName <> "Microsoft.Tri.Sensor.exe" // MDI Sensor
| where InitiatingProcessFileName <> "sensendr.exe" // MDE Device Discovery
| summarize dcount(RemoteIP) by InitiatingProcessFileName, InitiatingProcessFolderPath
```
### Sentinel
```
let TimeFrame = 24h; //Customizable h = hours, d = days
DeviceNetworkEvents
| where TimeGenerated > ago(TimeFrame)
| where RemotePort == 445
| where InitiatingProcessFileName <> "Microsoft.Tri.Sensor.exe" // MDI Sensor
| where InitiatingProcessFileName <> "sensendr.exe" // MDE Device Discovery
| summarize dcount(RemoteIP) by InitiatingProcessFileName, InitiatingProcessFolderPath
```

#### Versions
| Version | Comment |
| ---  | --- |
| 1.0 | Initial commit |
| 1.1 | Timespan update |


