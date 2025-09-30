# Forensics on Registry Run keys in Windows. 

## Query Information

#### Description
Registry Run keys can be used to establish persistence on a device. 

The detection covers the following registry key paths:

```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
```

## Defender XDR
```KQL
let CompromisedDevices = dynamic (["workstation01", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where RegistryKey endswith @'\Software\Microsoft\Windows\CurrentVersion\Run' or  RegistryKey endswith @'\Microsoft\Windows\CurrentVersion\RunOnce'
| project-reorder Timestamp, ActionType, DeviceId, DeviceName, RegistryKey, PreviousRegistryValueData, InitiatingProcessCommandLine
```

## Sentinel
```KQL
let CompromisedDevices = dynamic (["workstation01", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where RegistryKey endswith @'\Software\Microsoft\Windows\CurrentVersion\Run' or  RegistryKey endswith @'\Microsoft\Windows\CurrentVersion\RunOnce'
| project-reorder TimeGenerated, ActionType, DeviceId, DeviceName, RegistryKey, PreviousRegistryValueData, InitiatingProcessCommandLine
```