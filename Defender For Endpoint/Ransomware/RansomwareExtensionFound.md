# Triggers when a known ransomware extension has been found

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1486 | Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ |

#### Description
This query triggers when a file with a known ransomware extension has been found.

#### Risk
The file might indicate that files are encryped for ransomware.

#### References
- https://github.com/eshlomo1/Ransomware-NOTE

## Defender XDR
```KQL
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
## Sentinel
```KQL
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
