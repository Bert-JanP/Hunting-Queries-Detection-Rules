# List Local Firewall Additions

## Query Information

#### Description
List Local Firewall Additions

## Defender XDR
```KQL
DeviceProcessEvents
| where ProcessCommandLine has "firewall add"
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
| where ProcessCommandLine has "firewall add"
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.Updater.exe" // DFI sensor
| project-reorder
     TimeGenerated,
     DeviceName,
     AccountName,
     ProcessCommandLine,
     InitiatingProcessCommandLine
```
