# Runas with saved credentials

### Defender For Endpoint

```
DeviceProcessEvents
| where FileName == "runas.exe"
| extend TargetAccount = extract(@'user:(.*?) ', 1, ProcessCommandLine)
| where ProcessCommandLine contains "/savecred"
| project Timestamp, DeviceName, TargetAccount, ProcessCommandLine
```
### Sentinel
```
DeviceProcessEvents
| where FileName == "runas.exe"
| extend TargetAccount = extract(@'user:(.*?) ', 1, ProcessCommandLine)
| where ProcessCommandLine contains "/savecred"
| project TimeGenerated, DeviceName, TargetAccount, ProcessCommandLine
```



