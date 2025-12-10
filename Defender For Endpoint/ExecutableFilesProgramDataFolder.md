# Detect Executable Files in C:\ProgramData

## Query Information

#### Description
This query detects rare Executable files that are created in the folder C:\ProgramData\* and all the subfolders. It is not common that executable files are created in this folder and therefore the file creations should be investigated. An attacker can use those folders to 

Note: The query for Sentinel is different then the one for MDE, this is because the FileProfile function is used, which is currently not supported by Sentinel. Therefore I suggest running this query in MDE for the best results. 

#### Risk
An adversary creates payloads in the C:\ProgramData\* to stay undetected. 

#### References
- https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/
- https://logpoint.com/en/blog/inside-darkgate

## Defender XDR
```KQL
// The start of the folderpath in the Public directory.
let ProgramDataFolder = @'C:\ProgramData';
// List with Executable File Extensions, can be adjusted or changed.
let ExecutableFileExtensions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'msc','ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf', 'hta']);
// Prevalence Threshold, if the file exceeds this threshold it is likely to be benign.
let FilePrevalenceThreshold = 250;
DeviceFileEvents
| where FolderPath contains ProgramDataFolder
// Extract File Extension from the filename.
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Only list Files that are executable
| where FileExtension in~ (ExecutableFileExtensions)
| invoke FileProfile('SHA256', 10000)
// Filter based on FilePrevalenceThreshold
| where GlobalPrevalence <= FilePrevalenceThreshold
| project Timestamp, DeviceName, FileExtension, FolderPath, GlobalPrevalence, Signer, Publisher, ReportId, DeviceId
```

## Sentinel
```KQL
// The start of the folderpath in the Public directory.
let ProgramDataFolder = @'C:\Users\Public';
// List with Executable File Extensions, can be adjusted or changed.
let ExecutableFileExtensions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf', 'hta']);
DeviceFileEvents
| where FolderPath contains ProgramDataFolder
// Extract File Extension from the filename.
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Only list Files that are executable
| where FileExtension in~ (ExecutableFileExtensions)
```
