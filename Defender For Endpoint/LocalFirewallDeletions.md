# List Local Firewall Deletions

## Query Information

#### Description
List Local Firewall Deletions

## Defender XDR
```KQL
DeviceProcessEvents
| where ProcessCommandLine contains "firewall delete"
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.Updater.exe" // DFI sensor
| project-reorder
     Timestamp,
     DeviceName,
     AccountName,
     ProcessCommandLine,
     InitiatingProcessCommandLine
```

## Sentinel
```KQL
DeviceProcessEvents
| where ProcessCommandLine contains "firewall delete"
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.Updater.exe" // DFI sensor
| project-reorder
     TimeGenerated,
     DeviceName,
     AccountName,
     ProcessCommandLine,
     InitiatingProcessCommandLine
```
