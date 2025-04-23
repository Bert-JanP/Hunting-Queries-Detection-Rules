# Detect Executable Files in C:\Users\Public*

## Query Information

#### Description
This query detects rare Executable files that are created in the folder C:\Users\Public and all the subfolders. It is not common that executable files are created in this folder and therefore the file creations should be investigated. An attacker can use those folders to 

Note: The query for Sentinel is different then the one for MDE, this is because the FileProfile function is used, which is currently not supported by Sentinel. Therefore I suggest running this query in MDE for the best results. 

#### Risk
An adversary creates payloads in the C:\Users\Public to stay undetected. 

#### References
- https://twitter.com/malmoeb/status/1617052464288763910?s=46&t=5G3qrkaBu_D5VVZcFEwgdg
- https://www.mandiant.com/resources/blog/china-nexus-espionage-southeast-asia
- https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-203a
- https://securelist.com/server-side-attacks-cc-in-public-clouds-mdr-cases/107826/

## Defender XDR
```KQL
// The start of the folderpath in the Public directory.
let PublicFolder = @'C:\Users\Public';
// List with Executable File Extensions, can be adjusted or changed.
let ExecutableFileExtensions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'msc','ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf', 'hta']);
// Prevalence Threshold, if the file exceeds this threshold it is likely to be benign.
let FilePrevalenceThreshold = 250;
DeviceFileEvents
| where FolderPath contains PublicFolder
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
let PublicFolder = @'C:\Users\Public';
// List with Executable File Extensions, can be adjusted or changed.
let ExecutableFileExtensions = dynamic(['bat', 'cmd', 'com', 'cpl', 'ex', 'exe', 'jse', 'msc', 'ps1', 'reg', 'vb', 'vbe', 'ws', 'wsf', 'hta']);
DeviceFileEvents
| where FolderPath contains PublicFolder
// Extract File Extension from the filename.
| extend FileExtension = tostring(extract(@'.*\.(.*)', 1, FileName))
// Only list Files that are executable
| where FileExtension in~ (ExecutableFileExtensions)
```
