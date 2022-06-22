# Hunt for Local Firewall Additions
----
### Defender For Endpoint

```
DeviceProcessEvents
| where ProcessCommandLine contains "firewall add"
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.Updater.exe" // DFI sensor
| project-reorder
     Timestamp,
     DeviceName,
     AccountName,
     ProcessCommandLine,
     InitiatingProcessCommandLine

```
### Sentinel
```
DeviceProcessEvents
| where ProcessCommandLine contains "firewall add"
| where InitiatingProcessFileName != "Microsoft.Tri.Sensor.Updater.exe" // DFI sensor
| project-reorder
     TimeGenerated,
     DeviceName,
     AccountName,
     ProcessCommandLine,
     InitiatingProcessCommandLine

```



