# Detect new RDP connections

## Query Information

#### Description
Detect new RDP connections to devices that have not been established in the past 20 days

## Defender XDR
```KQL
let PreviousRDPConnections = materialize (
     DeviceNetworkEvents
     | where Timestamp > ago(20d)
     | where ActionType == "ConnectionSuccess"
     | where not(InitiatingProcessFileName == "Microsoft.Tri.Sensor.exe") 
// DFI Sensor
     | where RemotePort == 3389
     );
PreviousRDPConnections
| where Timestamp > ago(2d)
| join kind=leftanti (PreviousRDPConnections
     | where Timestamp > ago(1d))
     on DeviceName, InitiatingProcessAccountName
| project
     Timestamp,
     DeviceName,
     InitiatingProcessAccountDomain,
     InitiatingProcessAccountName,
     InitiatingProcessCommandLine,
     RemoteUrl,
     RemoteIP
| sort by Timestamp
```

## Sentinel
```KQL
let PreviousRDPConnections = materialize (
     DeviceNetworkEvents
     | where TimeGenerated > ago(20d)
     | where ActionType == "ConnectionSuccess"
     | where not(InitiatingProcessFileName == "Microsoft.Tri.Sensor.exe") 
// DFI Sensor
     | where RemotePort == 3389
     );
PreviousRDPConnections
| where TimeGenerated > ago(2d)
| join kind=leftanti (PreviousRDPConnections
     | where TimeGenerated > ago(1d))
     on DeviceName, InitiatingProcessAccountName
| project
     TimeGenerated,
     DeviceName,
     InitiatingProcessAccountDomain,
     InitiatingProcessAccountName,
     InitiatingProcessCommandLine,
     RemoteUrl,
     RemoteIP
| sort by TimeGenerated
```
