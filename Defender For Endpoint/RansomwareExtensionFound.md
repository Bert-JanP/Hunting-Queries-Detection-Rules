# Triggers when a known ransomware extension has been found
----
### Defender For Endpoint

```
let RansomwareExtensionsInput  = externaldata(Extension: string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-extension-list.txt"] with (format="txt", ignoreFirstRecord=True);
let RansomwareExtensionAddition = dynamic(['.misingfromabovelist']); // Add your missing / new extensions in this list.
let RansomwareExtensions = materialize (
     RansomwareExtensionsInput
     | distinct Extension
     | extend RawExtention = substring(Extension, 1, 
string_size(Extension))
     );
DeviceFileEvents
| where FileName has_any (RansomwareExtensions) or FileName has_any (RansomwareExtensionAddition)
| summarize
     arg_max(Timestamp, *),
     EncryptedFiles = make_set(FileName),
     Locations = make_set(FolderPath)
     by DeviceName
| extend TotalFileEncrypted = array_length(EncryptedFiles)
| project-reorder
     Timestamp,
     TotalFileEncrypted,
     EncryptedFiles,
     Locations,
     InitiatingProcessAccountName
| sort by TotalFileEncrypted
```
### Sentinel
```
let RansomwareExtensionsInput  = externaldata(Extension: string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-extension-list.txt"] with (format="txt", ignoreFirstRecord=True);
let RansomwareExtensionAddition = dynamic(['.misingfromabovelist']); // Add your missing / new extensions in this list.
let RansomwareExtensions = materialize (
     RansomwareExtensionsInput
     | distinct Extension
     | extend RawExtention = substring(Extension, 1, 
string_size(Extension))
     );
DeviceFileEvents
| where FileName has_any (RansomwareExtensions) or FileName has_any (RansomwareExtensionAddition)
| summarize
     arg_max(TimeGenerated, *),
     EncryptedFiles = make_set(FileName),
     Locations = make_set(FolderPath)
     by DeviceName
| extend TotalFileEncrypted = array_length(EncryptedFiles)
| project-reorder
     TimeGenerated,
     TotalFileEncrypted,
     EncryptedFiles,
     Locations,
     InitiatingProcessAccountName
| sort by TotalFileEncrypted
```



