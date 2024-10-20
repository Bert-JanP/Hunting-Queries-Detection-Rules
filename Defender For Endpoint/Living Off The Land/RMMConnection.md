# RMM Tools with connections

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1219 | Remote Access Software | https://attack.mitre.org/techniques/T1219/ |

#### Description
This query used the [LOLRMM](https://lolrmm.io/) API to fetch all filenames related to RMM tools. Based on the executable filenames it looks into all the *DeviceNetworkEvents* to find RMM tools that have made successful connections, indicating that the tool is used within your environment.

Credits to @Antonlovesdnb for quickly developing the API connection with externaldata to collect this data ([Tweet](https://x.com/Antonlovesdnb/status/1840823846720385482)).

#### Risk
An actor uses RRM tools to gain remote access to your environment.

#### References
- https://lolrmm.io/
- https://x.com/Antonlovesdnb/status/1840823846720385482

## Defender XDR
```KQL
// First part based on tweet by: @Antonlovesdnb https://x.com/Antonlovesdnb/status/1840823846720385482
let LOLRMM = externaldata(Name:string,Category:string,Description:string,Author:string,Date:datetime,LastModified:datetime,Website:string,Filename:string,OriginalFileName:string,PEDescription:string,Product:string,Privileges:string,Free:string,Verification:string,SupportedOS:string,Capabilities:string,
Vulnerabilities:string,InstallationPaths:string,Artifacts:string,Detections:string,References:string,Acknowledgement:string)[@"https://lolrmm.io/api/rmm_tools.csv"] with (format="csv", ignoreFirstRecord=True);
// Exclude any allowed RMMs based on name, example: dynamic(["Rapid7"]);
let AllowedRMM_Name = dynamic([]);
// Exclude any RMM based on executable name, example: dynamic(["mstsc.exe", "winscp.exe"]), used by multiple rmms
let AllowedRMM_executable = dynamic([]);
let ParsedExecutables = LOLRMM
    | where Name !in (AllowedRMM_Name)
    | distinct InstallationPaths
    | extend FileNames = extract_all(@"\b([a-zA-Z0-9 _-]+\.exe)", InstallationPaths)
    | mv-expand FileNames to typeof(string)
    | where isnotempty(FileNames)
    | project FileNames = tolower(FileNames)
    | distinct FileNames
    | where FileNames !in (AllowedRMM_executable);
DeviceNetworkEvents
| where tolower(InitiatingProcessFileName) in (ParsedExecutables)
| where ActionType == "ConnectionSuccess"
| summarize TotalEvents = count(), ExecutableCount = dcount(InitiatingProcessFileName), Executables = make_set(InitiatingProcessFileName) by DeviceName, DeviceId
```
## Sentinel
```KQL
// First part based on tweet by: @Antonlovesdnb https://x.com/Antonlovesdnb/status/1840823846720385482
let LOLRMM = externaldata(Name:string,Category:string,Description:string,Author:string,Date:datetime,LastModified:datetime,Website:string,Filename:string,OriginalFileName:string,PEDescription:string,Product:string,Privileges:string,Free:string,Verification:string,SupportedOS:string,Capabilities:string,
Vulnerabilities:string,InstallationPaths:string,Artifacts:string,Detections:string,References:string,Acknowledgement:string)[@"https://lolrmm.io/api/rmm_tools.csv"] with (format="csv", ignoreFirstRecord=True);
// Exclude any allowed RMMs based on name, example: dynamic(["Rapid7"]);
let AllowedRMM_Name = dynamic([]);
// Exclude any RMM based on executable name, example: dynamic(["mstsc.exe", "winscp.exe"]), used by multiple rmms
let AllowedRMM_executable = dynamic([]);
let ParsedExecutables = LOLRMM
    | where Name !in (AllowedRMM_Name)
    | distinct InstallationPaths
    | extend FileNames = extract_all(@"\b([a-zA-Z0-9 _-]+\.exe)", InstallationPaths)
    | mv-expand FileNames to typeof(string)
    | where isnotempty(FileNames)
    | project FileNames = tolower(FileNames)
    | distinct FileNames
    | where FileNames !in (AllowedRMM_executable);
DeviceNetworkEvents
| where tolower(InitiatingProcessFileName) in (ParsedExecutables)
| where ActionType == "ConnectionSuccess"
| summarize TotalEvents = count(), ExecutableCount = dcount(InitiatingProcessFileName), Executables = make_set(InitiatingProcessFileName) by DeviceName, DeviceId
```

