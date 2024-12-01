# Find all the processes a file has created and the associated FileNames, FileLocations and SHA1 hashes that the file has had. 
----
## Defender XDR

```KQL
// For the best results use SHA1
let MaliciousFileSHA1 = "e14f7ed43ab3ae9d31680eb74b043339eb6f87e7"; // Random generated SHA1 hash 9d833c959de5dd22d778c697cd0de8189c238b2e
let MaliciousFileName = "maliciousfilename.exe";
let SearchWindow = 48h; //Customizable h = hours, d = days
let FileInfoLocation = materialize (
     DeviceFileEvents
     | where Timestamp > ago(SearchWindow)
     | where ((not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName)))
     | summarize FileLocations = make_set(tolower(FolderPath)));
let FileInfoFileName = materialize (
     DeviceFileEvents
     | where Timestamp > ago(SearchWindow)
     | where ((not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName)))
     | summarize Filenames = make_set(tolower(FileName)));
let FileInfoFileSHA1 = materialize (
     DeviceFileEvents
     | where Timestamp > ago(SearchWindow)
     | where ((not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName)))
     | summarize FileInfoFileSHA1 = make_set(SHA1));
(union isfuzzy=true
     (FileInfoFileName), // Forensic information in set format available after last raw event
     (FileInfoLocation), // Forensic information in set format available after last raw event
     (FileInfoFileSHA1), // Forensic information in set format available after last raw event
     (DeviceProcessEvents
     | where tolower(InitiatingProcessCommandLine) has_any (FileInfoLocation) or InitiatingProcessSHA1 == MaliciousFileSHA1)
| sort by Timestamp
| project-reorder
     Filenames,
     FileLocations,
     FileInfoFileSHA1,
     Timestamp,
     DeviceName,
     ActionType,
     FileName,
     ProcessCommandLine,
     InitiatingProcessCommandLine
)
```
## Sentinel
```KQL
// For the best results use SHA1
let MaliciousFileSHA1 = "e14f7ed43ab3ae9d31680eb74b043339eb6f87e7"; // Random generated SHA1 hash 9d833c959de5dd22d778c697cd0de8189c238b2e
let MaliciousFileName = "maliciousfilename.exe";
let SearchWindow = 48h; //Customizable h = hours, d = days
let FileInfoLocation = materialize (
     DeviceFileEvents
     | where TimeGenerated > ago(SearchWindow)
     | where ((not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName)))
     | summarize FileLocations = make_set(tolower(FolderPath)));
let FileInfoFileName = materialize (
     DeviceFileEvents
     | where TimeGenerated > ago(SearchWindow)
     | where ((not(isempty(MaliciousFileSHA1)) and SHA1 == 
MaliciousFileSHA1) or (isempty(MaliciousFileSHA1) and tolower(FileName) 
== tolower(MaliciousFileName)))
     | summarize Filenames = make_set(tolower(FileName)));
let FileInfoFileSHA1 = materialize (
     DeviceFileEvents
     | where TimeGenerated > ago(SearchWindow)
     | where ((not(isempty(MaliciousFileSHA1)) and SHA1 == MaliciousFileSHA1) or (isempty(MaliciousFileSHA1) and tolower(FileName) == tolower(MaliciousFileName)))
     | summarize FileInfoFileSHA1 = make_set(SHA1));
(union isfuzzy=true
     (FileInfoFileName), // Forensic information in set format available after last raw event
     (FileInfoLocation), // Forensic information in set format available after last raw event
     (FileInfoFileSHA1), // Forensic information in set format available after last raw event
     (DeviceProcessEvents
     | where tolower(InitiatingProcessCommandLine) has_any (FileInfoLocation) or InitiatingProcessSHA1 == MaliciousFileSHA1)
| sort by TimeGenerated
| project-reorder
     Filenames,
     FileLocations,
     FileInfoFileSHA1,
     TimeGenerated,
     DeviceName,
     ActionType,
     FileName,
     ProcessCommandLine,
     InitiatingProcessCommandLine
)
```



