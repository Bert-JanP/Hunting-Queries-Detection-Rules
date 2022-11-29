# Windows Network Sniffing

Mitre Technique: [T1040](https://attack.mitre.org/techniques/T1040/)

Packet Monitor Documentation: [Packed Monitor](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon)


### Defender For Endpoint

```
DeviceProcessEvents
| where FileName == "PktMon.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```
### Sentinel
```
DeviceProcessEvents
| where FileName == "PktMon.exe"
| project TimeGenerated, DeviceName, ProcessCommandLine
```



