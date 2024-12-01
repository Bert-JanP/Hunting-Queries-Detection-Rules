# Forensics on Registry Run keys in Windows. Registry Run keys can be used to establish persistence on a device. 
----
## Defender XDR

```
let RegistryRunKeys = dynamic 
([@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",  
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"]);
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where RegistryKey has_any (RegistryRunKeys)
| extend RegistryChangeInfo = bag_pack("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalRunKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```
## Sentinel
```
let RegistryRunKeys = dynamic 
([@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"]);
let CompromisedDevices = dynamic (["laptop1", "server1"]);
let SearchWindow = 7d; //Customizable h = hours, d = days
DeviceRegistryEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where RegistryKey has_any (RegistryRunKeys)
| extend RegistryChangeInfo = pack_dictionary("RegistryKey", RegistryKey, "Action Performed", ActionType, "Old Value", PreviousRegistryKey, "New Value", RegistryValueData)
| summarize TotalRunKeysChanged = count(), RegistryInfo = make_set(RegistryChangeInfo) by DeviceName
```



