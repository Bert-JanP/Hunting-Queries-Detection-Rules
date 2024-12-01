# Find the DFE Antivirus events on compromised devices. FileInfo is stored in JSON format.
----
## Defender XDR

```
let CompromisedDevices = dynamic (["laptop1", "server2"]);
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceEvents
| where Timestamp > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where ActionType == "AntivirusDetection"
| extend FileInfo = pack_dictionary("FileName", FileName, "FileLocation", FolderPath, "SHA1", SHA1, "SHA256", SHA256, "MD5", MD5)
| summarize TotalDetections = count(), MaliciousFiles = make_set(FileInfo) by DeviceName
```
## Sentinel
```
let CompromisedDevices = dynamic (["laptop1", "server2"]);
let SearchWindow = 48h; //Customizable h = hours, d = days
DeviceEvents
| where TimeGenerated > ago(SearchWindow)
| where DeviceName has_any (CompromisedDevices)
| where ActionType == "AntivirusDetection"
| extend FileInfo = pack_dictionary("FileName", FileName, "FileLocation", FolderPath, "SHA1", SHA1, "SHA256", SHA256, "MD5", MD5)
| summarize TotalDetections = count(), MaliciousFiles = make_set(FileInfo) by DeviceName
```



